package fxa

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// APIError is an error returned by the FxA auth server (JSON body with
// code/errno/message), or a transport failure.
type APIError struct {
	Status  int    `json:"-"`
	Code    int    `json:"code"`
	Errno   int    `json:"errno"`
	Message string `json:"message"`
	Info    string `json:"info,omitempty"`
	// Validation details present on errno 107 (invalid parameter) responses.
	Validation *struct {
		Source string   `json:"source"`
		Keys   []string `json:"keys"`
	} `json:"validation,omitempty"`
}

func (e *APIError) Error() string {
	msg := e.Message
	if msg == "" && e.Validation != nil && len(e.Validation.Keys) > 0 {
		msg = "invalid parameter(s): " + strings.Join(e.Validation.Keys, ", ")
	}
	if msg == "" {
		return fmt.Sprintf("fxa: HTTP %d", e.Status)
	}
	return fmt.Sprintf("fxa: HTTP %d errno %d: %s", e.Status, e.Errno, msg)
}

// Well-known FxA errnos.
const (
	ErrnoUnknownAccount    = 102
	ErrnoIncorrectPassword = 103
	ErrnoBadUnblockCode    = 107
	ErrnoUnblockRequired   = 125
	ErrnoAccountUnverified = 201
)

func IsErrno(err error, errno int) bool {
	var apiErr *APIError
	return errors.As(err, &apiErr) && apiErr.Errno == errno
}

// Session is an authenticated FxA session.
type Session struct {
	Email              string `json:"email,omitempty"`
	UID                string `json:"uid"`
	Token              string `json:"sessionToken"` // hex
	Verified           bool   `json:"verified"`
	VerificationMethod string `json:"verificationMethod,omitempty"`
	AuthAt             int64  `json:"authAt"`
}

// Client talks to the FxA auth server (default https://api.accounts.firefox.com/v1).
type Client struct {
	BaseURL string
	HTTP    *http.Client
}

func NewClient(baseURL string) *Client {
	return &Client{
		BaseURL: strings.TrimSuffix(baseURL, "/"),
		HTTP:    &http.Client{Timeout: 30 * time.Second},
	}
}

// call performs an API request; auth is a full Authorization header value or "".
func (c *Client) call(method, path string, body any, authHeader string, out any) error {
	var reader io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		reader = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, c.BaseURL+path, reader)
	if err != nil {
		return err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	// The FxA auth server answers 406 Not Acceptable without this header.
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "ffvpn/0.1 (Firefox VPN proxy client)")
	if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return fmt.Errorf("fxa: request to %s failed: %w", path, err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode >= 400 || resp.StatusCode < 200 {
		apiErr := &APIError{Status: resp.StatusCode}
		if jsonErr := json.Unmarshal(data, apiErr); jsonErr != nil {
			// Non-JSON error bodies (framework/WAF responses): keep a
			// short snippet so failures stay diagnosable.
			snippet := strings.TrimSpace(string(data))
			if len(snippet) > 120 {
				snippet = snippet[:120]
			}
			apiErr.Message = snippet
		} else if apiErr.Message == "" {
			// hapi-style errors use "error" for the reason phrase.
			var hapi struct {
				ErrorName string `json:"error"`
			}
			if json.Unmarshal(data, &hapi) == nil {
				apiErr.Message = hapi.ErrorName
			}
		}
		return apiErr
	}
	if out != nil {
		if err := json.Unmarshal(data, out); err != nil {
			return fmt.Errorf("fxa: %s: invalid response: %w", path, err)
		}
	}
	return nil
}

// credentialsStatus reports which key-stretch version an account uses.
type credentialsStatus struct {
	CurrentVersion string `json:"currentVersion"`
	ClientSalt     string `json:"clientSalt"`
}

// Login signs in with email+password. It follows the current FxA key-stretch
// protocol: ask the server for the account's stretch version (v1 salts with
// the email, v2 salts with a server-issued clientSalt and more PBKDF2 rounds).
func (c *Client) Login(email, password, unblockCode string) (*Session, error) {
	body := map[string]any{
		"email":  email,
		"reason": "login",
	}
	var status credentialsStatus
	err := c.call(http.MethodPost, "/account/credentials/status", map[string]string{"email": email}, "", &status)
	switch {
	case err == nil && status.CurrentVersion == "v2" && status.ClientSalt != "":
		body["authPW"] = AuthPW(QuickStretchV2(status.ClientSalt, password))
	case err == nil && status.CurrentVersion == "v1":
		body["authPW"] = AuthPW(QuickStretchV1(email, password))
	case IsErrno(err, ErrnoUnknownAccount):
		// Nothing to do; login below will fail with the same error.
		body["authPW"] = AuthPW(QuickStretchV1(email, password))
	default:
		// Status endpoint unavailable: fall back to v1 stretching.
		body["authPW"] = AuthPW(QuickStretchV1(email, password))
	}
	if unblockCode != "" {
		body["unblockCode"] = unblockCode
	}

	var session Session
	session.Email = email
	if err := c.call(http.MethodPost, "/account/login", body, "", &session); err != nil {
		return nil, err
	}
	return &session, nil
}

// SessionStatus validates a session token and returns the account uid.
func (c *Client) SessionStatus(s *Session) (string, error) {
	auth, err := SessionAuthHeader(s.Token)
	if err != nil {
		return "", err
	}
	var out struct {
		UID string `json:"uid"`
	}
	if err := c.call(http.MethodGet, "/session/status", nil, auth, &out); err != nil {
		return "", err
	}
	return out.UID, nil
}

// TOTPExists reports whether the account has TOTP two-factor auth enabled.
func (c *Client) TOTPExists(s *Session) (bool, error) {
	auth, err := SessionAuthHeader(s.Token)
	if err != nil {
		return false, err
	}
	var out struct {
		Exists bool `json:"exists"`
	}
	if err := c.call(http.MethodGet, "/totp/exists", nil, auth, &out); err != nil {
		return false, err
	}
	return out.Exists, nil
}

// VerifyTOTP completes two-factor verification of the session.
func (c *Client) VerifyTOTP(s *Session, code string) error {
	auth, err := SessionAuthHeader(s.Token)
	if err != nil {
		return err
	}
	var out struct {
		Success bool `json:"success"`
	}
	if err := c.call(http.MethodPost, "/session/verify/totp", map[string]string{"code": code}, auth, &out); err != nil {
		return err
	}
	if !out.Success {
		return errors.New("fxa: TOTP code rejected")
	}
	s.Verified = true
	return nil
}

type emailStatus struct {
	Verified        bool `json:"verified"`
	EmailVerified   bool `json:"emailVerified"`
	SessionVerified bool `json:"sessionVerified"`
}

// WaitVerified blocks until the session is verified (sign-in confirmation
// email clicked, or TOTP verified) or the timeout elapses.
func (c *Client) WaitVerified(s *Session, timeout time.Duration, pollInterval time.Duration) error {
	deadline := time.Now().Add(timeout)
	for {
		auth, err := SessionAuthHeader(s.Token)
		if err != nil {
			return err
		}
		var st emailStatus
		if err := c.call(http.MethodGet, "/recovery_email/status", nil, auth, &st); err != nil {
			return err
		}
		if st.Verified || st.SessionVerified {
			s.Verified = true
			return nil
		}
		if time.Now().After(deadline) {
			return errors.New("fxa: session still unverified after timeout")
		}
		time.Sleep(pollInterval)
	}
}
