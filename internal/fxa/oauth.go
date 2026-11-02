package fxa

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"sync"
	"time"
)

// OAuthClient talks to the FxA OAuth server (default
// https://oauth.accounts.firefox.com/v1) and trades a session token for an
// OAuth token via the assertion-less PKCE flow used by Firefox desktop.
type OAuthClient struct {
	BaseURL  string
	ClientID string // e.g. Firefox Desktop: 5882386c6d801776
	HTTP     *http.Client

	// Logf receives progress lines (solving a challenge takes seconds); nil
	// writes to the standard logger.
	Logf func(format string, args ...any)

	// jar holds the anti-bot cookie earned from Fastly; HTTP uses it.
	jar *cookiejar.Jar
	// challengeMu serializes solvers, which would otherwise race on jar.
	challengeMu sync.Mutex
}

func NewOAuthClient(baseURL, clientID string) *OAuthClient {
	// A jar is what carries the challenge answer; if one cannot be created
	// the client still works for the endpoints the edge does not block.
	jar, _ := cookiejar.New(nil)
	return &OAuthClient{
		BaseURL:  strings.TrimSuffix(baseURL, "/"),
		ClientID: clientID,
		HTTP:     &http.Client{Timeout: 30 * time.Second, Jar: jar},
		jar:      jar,
	}
}

// solveChallenge earns the anti-bot cookie for this client's API origin and
// puts it in the client's jar; the 406 retry loop in post uses it.
func (c *OAuthClient) solveChallenge() error {
	c.challengeMu.Lock()
	defer c.challengeMu.Unlock()
	return solveChallenge(c.HTTP.Transport, c.jar, originOf(c.BaseURL), c.Logf)
}

func b64urlNoPad(b []byte) string {
	return base64.RawURLEncoding.EncodeToString(b)
}

func randomB64(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return b64urlNoPad(b), nil
}

// TokenForSession returns a short-lived OAuth access token for the given
// scopes (e.g. ["profile", "https://identity.mozilla.com/apps/vpn"]).
//
// Flow: POST /oauth/authorization (session-token Bearer auth, PKCE challenge)
// -> parse the auth code from the returned redirect URL -> POST /token with
// the code verifier.
func (c *OAuthClient) TokenForSession(s *Session, scopes []string) (string, error) {
	auth, err := SessionAuthHeader(s.Token)
	if err != nil {
		return "", err
	}
	verifier, err := randomB64(32)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256([]byte(verifier))
	state, err := randomB64(24)
	if err != nil {
		return "", err
	}

	authBody := map[string]any{
		"client_id": c.ClientID,
		"state":     state,
		// FxA validates scope as a space-separated string (matching
		// Firefox's scopes.join(" ")); a JSON array yields errno 107.
		"scope":                 strings.Join(scopes, " "),
		"code_challenge":        b64urlNoPad(sum[:]),
		"code_challenge_method": "S256",
	}
	authResp, err := c.post("/oauth/authorization", authBody, auth)
	if err != nil {
		return "", err
	}
	redirect, _ := authResp["redirect"].(string)
	if redirect == "" {
		return "", errors.New("fxa oauth: no redirect in authorization response")
	}
	u, err := url.Parse(redirect)
	if err != nil {
		return "", fmt.Errorf("fxa oauth: bad redirect URL: %w", err)
	}
	q := u.Query()
	if got := q.Get("state"); got != state {
		return "", errors.New("fxa oauth: state mismatch in redirect")
	}
	code := q.Get("code")
	if code == "" {
		return "", fmt.Errorf("fxa oauth: no code in redirect (error=%s)", q.Get("error"))
	}

	tokenResp, err := c.post("/token", map[string]any{
		"code":          code,
		"client_id":     c.ClientID,
		"code_verifier": verifier,
	}, "")
	if err != nil {
		return "", err
	}
	accessToken, _ := tokenResp["access_token"].(string)
	if accessToken == "" {
		return "", errors.New("fxa oauth: no access_token in token response")
	}
	return accessToken, nil
}

// post performs one OAuth API request. Like the auth client, the OAuth server
// sits behind the Fastly edge, which blocks non-browser clients with a bare
// HTTP 406 that carries no FxA error payload; a blocked request solves the
// challenge and is retried instead of failing.
func (c *OAuthClient) post(path string, body map[string]any, authHeader string) (map[string]any, error) {
	payload, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}

	var status int
	var data []byte
	for attempt := 1; ; attempt++ {
		var err error
		status, data, err = c.send(path, payload, authHeader)
		if err != nil {
			return nil, err
		}
		if status != http.StatusNotAcceptable {
			break
		}
		if c.jar == nil || attempt > maxChallengeAttempts {
			return nil, &APIError{Status: status, Message: fmt.Sprintf(
				"Fastly anti-bot challenge not cleared after %d attempts", attempt)}
		}
		if err := c.solveChallenge(); err != nil {
			return nil, &APIError{Status: status, Message: fmt.Sprintf("Fastly anti-bot challenge: %v", err)}
		}
	}

	if status < 200 || status >= 300 {
		var apiErr APIError
		if json.Unmarshal(data, &apiErr) == nil && apiErr.Message != "" {
			apiErr.Status = status
			return nil, &apiErr
		}
		return nil, fmt.Errorf("fxa oauth: %s: HTTP %d: %s", path, status, strings.TrimSpace(string(data)))
	}
	var out map[string]any
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, fmt.Errorf("fxa oauth: %s: invalid JSON response: %w", path, err)
	}
	return out, nil
}

// send performs one request and returns its status and body. The payload is
// re-readable because a blocked request is sent again after the challenge.
func (c *OAuthClient) send(path string, payload []byte, authHeader string) (int, []byte, error) {
	req, err := http.NewRequest(http.MethodPost, c.BaseURL+path, bytes.NewReader(payload))
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	// The FxA servers answer 406 Not Acceptable without this header.
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", firefoxUserAgent())
	if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return 0, nil, fmt.Errorf("fxa oauth: request to %s failed: %w", path, err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return resp.StatusCode, nil, err
	}
	return resp.StatusCode, data, nil
}
