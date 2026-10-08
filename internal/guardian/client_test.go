package guardian

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// makeJWT builds a syntactically valid JWT with the given nbf/exp (signature
// is a placeholder: signature verification happens server-side at the edge).
func makeJWT(nbf, exp int64) string {
	b64 := func(v any) string {
		b, _ := json.Marshal(v)
		return base64.RawURLEncoding.EncodeToString(b)
	}
	return b64(map[string]string{"alg": "RS256", "typ": "JWT"}) + "." +
		b64(map[string]any{
			"sub": "user-1",
			"aud": "https://proxy.example",
			"iat": nbf, "nbf": nbf, "exp": exp,
			"iss": "guardian-test",
		}) + ".c2lnbmF0dXJl"
}

func TestParseProxyPassAndRotation(t *testing.T) {
	now := time.Now()
	pass, err := ParseProxyPass(makeJWT(now.Unix()-10, now.Unix()+300))
	if err != nil {
		t.Fatal(err)
	}
	if !pass.Valid(now) {
		t.Fatal("pass should be valid now")
	}
	wantRotation := time.Unix(now.Unix()+300, 0).Add(-2 * time.Minute)
	if !pass.RotationTime().Equal(wantRotation) {
		t.Fatalf("RotationTime = %v, want %v", pass.RotationTime(), wantRotation)
	}
	if pass.Valid(time.Unix(now.Unix()+301, 0)) {
		t.Fatal("pass should be expired after exp")
	}
	if _, err := ParseProxyPass("not-a-jwt"); err == nil {
		t.Fatal("expected error for non-JWT token")
	}
}

func TestActivateAndProxyPass(t *testing.T) {
	now := time.Now()
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/fpn/activate", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer OATK" {
			t.Errorf("activate: bad auth header %q", r.Header.Get("Authorization"))
		}
		json.NewEncoder(w).Encode(map[string]any{
			"subscribed": true, "uid": 42, "maxBytes": "107374182400", "limited_bandwidth": true,
		})
	})
	mux.HandleFunc("/api/v1/fpn/token", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Quota-Limit", "107374182400")
		w.Header().Set("X-Quota-Remaining", "107374000000")
		w.Header().Set("X-Quota-Reset", time.Now().Add(24*time.Hour).UTC().Format(time.RFC3339))
		json.NewEncoder(w).Encode(map[string]string{"token": makeJWT(now.Unix()-5, now.Unix()+600)})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	c := NewClient(srv.URL)
	ent, _, err := c.Activate("OATK")
	if err != nil {
		t.Fatal(err)
	}
	if !ent.Subscribed || ent.UID != 42 || ent.MaxBytes != "107374182400" {
		t.Fatalf("unexpected entitlement: %+v", ent)
	}

	pass, usage, err := c.ProxyPass("OATK")
	if err != nil {
		t.Fatal(err)
	}
	if !pass.Valid(now.Add(time.Second)) {
		t.Fatal("pass should be valid")
	}
	if usage == nil || usage.Exhausted() {
		t.Fatalf("unexpected usage: %+v", usage)
	}
}

func TestErrorMapping(t *testing.T) {
	cases := []struct {
		status int
		kind   ErrorKind
	}{
		{http.StatusUnauthorized, KindUnauthorized},
		{http.StatusForbidden, KindNotEntitled},
		{http.StatusTooManyRequests, KindQuota},
		{http.StatusUnavailableForLegalReasons, KindRegion},
		{http.StatusBadGateway, KindServer},
	}
	for _, tc := range cases {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if tc.status == http.StatusTooManyRequests {
				w.Header().Set("Retry-After", "120")
			}
			w.WriteHeader(tc.status)
			w.Write([]byte(`{"error":"nope"}`))
		}))
		c := NewClient(srv.URL)
		_, _, err := c.ProxyPass("OATK")
		srv.Close()
		if err == nil {
			t.Fatalf("status %d: expected error", tc.status)
		}
		var gerr *Error
		if !errors.As(err, &gerr) {
			t.Fatalf("status %d: not a guardian.Error: %v", tc.status, err)
		}
		if gerr.Kind != tc.kind {
			t.Fatalf("status %d: kind = %v, want %v", tc.status, gerr.Kind, tc.kind)
		}
		if tc.status == http.StatusTooManyRequests && gerr.RetryAfter != 120*time.Second {
			t.Fatalf("Retry-After not parsed: %v", gerr.RetryAfter)
		}
	}
}

func TestUsageHeaders(t *testing.T) {
	h := http.Header{}
	h.Set("X-Quota-Unlimited", "true")
	u := usageFromHeaders(h)
	if u == nil || !u.Unlimited || u.Exhausted() {
		t.Fatalf("unlimited usage mishandled: %+v", u)
	}
	h = http.Header{}
	h.Set("X-Quota-Limit", "1000")
	h.Set("X-Quota-Remaining", "0")
	h.Set("X-Quota-Reset", "2026-11-01T00:00:00Z")
	u = usageFromHeaders(h)
	if u == nil || !u.Exhausted() {
		t.Fatalf("exhausted usage not detected: %+v", u)
	}
	if !strings.Contains(u.Limit, "1000") {
		t.Fatalf("limit lost: %q", u.Limit)
	}
}
