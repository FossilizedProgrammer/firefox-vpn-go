package fxa

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// OAuthClient talks to the FxA OAuth server (default
// https://oauth.accounts.firefox.com/v1) and trades a session token for an
// OAuth token via the assertion-less PKCE flow used by Firefox desktop.
type OAuthClient struct {
	BaseURL  string
	ClientID string // e.g. Firefox Desktop: 5882386c6d801776
	HTTP     *http.Client
}

func NewOAuthClient(baseURL, clientID string) *OAuthClient {
	return &OAuthClient{
		BaseURL:  strings.TrimSuffix(baseURL, "/"),
		ClientID: clientID,
		HTTP:     &http.Client{Timeout: 30 * time.Second},
	}
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

func (c *OAuthClient) post(path string, body map[string]any, authHeader string) (map[string]any, error) {
	b, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequest(http.MethodPost, c.BaseURL+path, strings.NewReader(string(b)))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	// The FxA servers answer 406 Not Acceptable without this header.
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "ffvpn/0.1 (Firefox VPN proxy client)")
	if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fxa oauth: request to %s failed: %w", path, err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		var apiErr APIError
		if json.Unmarshal(data, &apiErr) == nil && apiErr.Message != "" {
			apiErr.Status = resp.StatusCode
			return nil, &apiErr
		}
		return nil, fmt.Errorf("fxa oauth: %s: HTTP %d: %s", path, resp.StatusCode, strings.TrimSpace(string(data)))
	}
	var out map[string]any
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, fmt.Errorf("fxa oauth: %s: invalid JSON response: %w", path, err)
	}
	return out, nil
}
