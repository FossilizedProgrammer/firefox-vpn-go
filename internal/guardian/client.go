// Package guardian is a client for Mozilla's Guardian service
// (https://vpn.mozilla.com), the subscription backend that issues short-lived
// JWT "proxy passes" for the browser's IP Protection proxy edge.
package guardian

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// Error kinds reported by Guardian. HTTP status meanings per the Firefox
// GuardianClient implementation:
//
//	401 unauthorized, 403 not entitled (no subscription),
//	429 quota exhausted, 451 region not served.
type ErrorKind int

const (
	KindOther ErrorKind = iota
	KindUnauthorized
	KindNotEntitled
	KindQuota
	KindRegion
	KindServer
)

type Error struct {
	Status     int
	Kind       ErrorKind
	RetryAfter time.Duration
	Body       string
}

func (e *Error) Error() string {
	switch e.Kind {
	case KindUnauthorized:
		return fmt.Sprintf("guardian: unauthorized (HTTP %d)", e.Status)
	case KindNotEntitled:
		return fmt.Sprintf("guardian: account has no VPN entitlement (HTTP %d)", e.Status)
	case KindQuota:
		return fmt.Sprintf("guardian: bandwidth quota exceeded (HTTP %d)", e.Status)
	case KindRegion:
		return fmt.Sprintf("guardian: service not available in this region (HTTP %d)", e.Status)
	case KindServer:
		return fmt.Sprintf("guardian: server error (HTTP %d)", e.Status)
	default:
		return fmt.Sprintf("guardian: unexpected HTTP %d: %s", e.Status, e.Body)
	}
}

// Entitlement is the user's proxy-service entitlement from /status or /activate.
type Entitlement struct {
	Subscribed       bool   `json:"subscribed"`
	UID              int64  `json:"uid"`
	MaxBytes         string `json:"maxBytes"`
	LimitedBandwidth bool   `json:"limited_bandwidth"`
}

// Usage is the bandwidth quota state, carried in X-Quota-* response headers.
type Usage struct {
	Unlimited bool
	Limit     string
	Remaining string
	Reset     time.Time
}

func (u *Usage) Exhausted() bool {
	if u == nil || u.Unlimited {
		return false
	}
	n, err := strconv.ParseInt(u.Remaining, 10, 64)
	return err == nil && n <= 0
}

// ProxyPass is a short-lived JWT that authenticates against the proxy edge.
// Claims: sub, aud, iat, nbf, exp, iss. The edge verifies the signature.
type ProxyPass struct {
	Token string
	NBF   int64
	Exp   int64
}

func (p *ProxyPass) Valid(now time.Time) bool {
	return p != nil &&
		!now.Before(time.Unix(p.NBF, 0)) &&
		now.Before(time.Unix(p.Exp, 0))
}

// RotationTime is when a new pass should be fetched (2 minutes before expiry,
// matching Firefox's rotation schedule).
func (p *ProxyPass) RotationTime() time.Time {
	return time.Unix(p.Exp, 0).Add(-2 * time.Minute)
}

// ParseProxyPass decodes a JWT payload (no signature check client-side: the
// proxy edge enforces it).
func ParseProxyPass(token string) (*ProxyPass, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, errors.New("guardian: token is not a JWT")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("guardian: bad JWT payload: %w", err)
	}
	var claims struct {
		NBF int64 `json:"nbf"`
		Exp int64 `json:"exp"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, fmt.Errorf("guardian: bad JWT claims: %w", err)
	}
	if claims.NBF == 0 || claims.Exp <= claims.NBF {
		return nil, errors.New("guardian: JWT missing nbf/exp claims")
	}
	return &ProxyPass{Token: token, NBF: claims.NBF, Exp: claims.Exp}, nil
}

// Client talks to Guardian.
type Client struct {
	BaseURL string // default https://vpn.mozilla.com
	HTTP    *http.Client
}

func NewClient(baseURL string) *Client {
	return &Client{
		BaseURL: strings.TrimSuffix(baseURL, "/"),
		HTTP:    &http.Client{Timeout: 30 * time.Second},
	}
}

func (c *Client) do(method, path, oauthToken string, out any) (*Usage, error) {
	req, err := http.NewRequest(method, c.BaseURL+path, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+oauthToken)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "ffvpn/0.1 (Firefox VPN proxy client)")

	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, fmt.Errorf("guardian: request to %s failed: %w", path, err)
	}
	defer resp.Body.Close()

	usage := usageFromHeaders(resp.Header)
	if resp.StatusCode != http.StatusOK {
		gerr := &Error{Status: resp.StatusCode, Body: strings.TrimSpace(readBody(resp))}
		switch resp.StatusCode {
		case http.StatusUnauthorized:
			gerr.Kind = KindUnauthorized
		case http.StatusForbidden:
			gerr.Kind = KindNotEntitled
		case http.StatusTooManyRequests:
			gerr.Kind = KindQuota
			if ra := resp.Header.Get("Retry-After"); ra != "" {
				if secs, err := strconv.Atoi(ra); err == nil {
					gerr.RetryAfter = time.Duration(secs) * time.Second
				}
			}
		case http.StatusUnavailableForLegalReasons:
			gerr.Kind = KindRegion
		default:
			if resp.StatusCode >= 500 {
				gerr.Kind = KindServer
			}
		}
		return usage, gerr
	}
	if out != nil {
		if err := json.Unmarshal([]byte(readBody(resp)), out); err != nil {
			return usage, fmt.Errorf("guardian: %s: invalid response: %w", path, err)
		}
	}
	return usage, nil
}

func readBody(resp *http.Response) string {
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return string(b)
}

func usageFromHeaders(h http.Header) *Usage {
	if h.Get("X-Quota-Unlimited") == "true" {
		return &Usage{Unlimited: true}
	}
	limit, remaining, reset := h.Get("X-Quota-Limit"), h.Get("X-Quota-Remaining"), h.Get("X-Quota-Reset")
	if limit == "" || remaining == "" || reset == "" {
		return nil
	}
	u := &Usage{Limit: limit, Remaining: remaining}
	if t, err := time.Parse(time.RFC3339, reset); err == nil {
		u.Reset = t
	}
	return u
}

// Activate registers the FxA account with Guardian and returns entitlement.
func (c *Client) Activate(oauthToken string) (*Entitlement, *Usage, error) {
	var ent Entitlement
	usage, err := c.do(http.MethodPost, "/api/v1/fpn/activate", oauthToken, &ent)
	if err != nil {
		return nil, usage, err
	}
	return &ent, usage, nil
}

// Status fetches the current entitlement without activating.
func (c *Client) Status(oauthToken string) (*Entitlement, *Usage, error) {
	var ent Entitlement
	usage, err := c.do(http.MethodGet, "/api/v1/fpn/status", oauthToken, &ent)
	if err != nil {
		return nil, usage, err
	}
	return &ent, usage, nil
}

// ProxyPass fetches a fresh JWT pass for the proxy edge.
func (c *Client) ProxyPass(oauthToken string) (*ProxyPass, *Usage, error) {
	var out struct {
		Token string `json:"token"`
	}
	usage, err := c.do(http.MethodGet, "/api/v1/fpn/token", oauthToken, &out)
	if err != nil {
		return nil, usage, err
	}
	pass, err := ParseProxyPass(out.Token)
	if err != nil {
		return nil, usage, err
	}
	return pass, usage, nil
}
