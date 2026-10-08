package fxa

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// fakeFxA stands in for the auth + OAuth servers and records what the client
// sent, so the protocol flow can be asserted end to end.
type fakeFxA struct {
	t *testing.T

	authSrv  *httptest.Server
	oauthSrv *httptest.Server

	mu          sync.Mutex
	lastAuthPW  string
	totpCode    string
	challenge   string
	oauthAuth   string
	codeVerifer string
}

func newFakeFxA(t *testing.T, sessionVerified bool, stretchVersion string) *fakeFxA {
	f := &fakeFxA{t: t}

	authMux := http.NewServeMux()
	authMux.HandleFunc("/account/credentials/status", func(w http.ResponseWriter, r *http.Request) {
		resp := map[string]string{"currentVersion": stretchVersion}
		if stretchVersion == "v2" {
			resp["clientSalt"] = vecClientSalt
		}
		json.NewEncoder(w).Encode(resp)
	})
	authMux.HandleFunc("/account/login", func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		json.NewDecoder(r.Body).Decode(&body)
		f.mu.Lock()
		f.lastAuthPW, _ = body["authPW"].(string)
		f.mu.Unlock()
		json.NewEncoder(w).Encode(map[string]any{
			"uid":                "abcd1234abcd1234",
			"sessionToken":       vecSessionToken,
			"verified":           sessionVerified,
			"verificationMethod": "email",
			"authAt":             1750000000,
		})
	})
	authMux.HandleFunc("/session/status", func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer fxs_") {
			t.Errorf("session/status: missing prefixed bearer auth: %q", r.Header.Get("Authorization"))
		}
		json.NewEncoder(w).Encode(map[string]string{"uid": "abcd1234abcd1234"})
	})
	authMux.HandleFunc("/totp/exists", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]bool{"exists": true})
	})
	authMux.HandleFunc("/session/verify/totp", func(w http.ResponseWriter, r *http.Request) {
		var body map[string]string
		json.NewDecoder(r.Body).Decode(&body)
		f.mu.Lock()
		f.totpCode = body["code"]
		f.mu.Unlock()
		json.NewEncoder(w).Encode(map[string]bool{"success": body["code"] == "123456"})
	})
	authMux.HandleFunc("/recovery_email/status", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]bool{"verified": sessionVerified, "sessionVerified": sessionVerified})
	})

	oauthMux := http.NewServeMux()
	oauthMux.HandleFunc("/oauth/authorization", func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		json.NewDecoder(r.Body).Decode(&body)
		// The server validates scope as a space-separated string; an array
		// is rejected with errno 107 in production.
		if _, ok := body["scope"].(string); !ok {
			t.Errorf("scope must be a string, got %T", body["scope"])
		}
		f.mu.Lock()
		f.oauthAuth = r.Header.Get("Authorization")
		if cc, _ := body["code_challenge"].(string); cc != "" {
			f.challenge = cc
		}
		state, _ := body["state"].(string)
		f.mu.Unlock()
		if !strings.HasPrefix(f.oauthAuth, "Bearer fxs_") {
			t.Errorf("oauth/authorization: missing prefixed bearer auth")
		}
		json.NewEncoder(w).Encode(map[string]string{
			"redirect": "https://accounts.example/oauth/success?code=TESTCODE&state=" + state,
		})
	})
	oauthMux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		json.NewDecoder(r.Body).Decode(&body)
		f.mu.Lock()
		f.codeVerifer, _ = body["code_verifier"].(string)
		f.mu.Unlock()
		sum := sha256.Sum256([]byte(f.codeVerifer))
		if f.challenge != "" && base64.RawURLEncoding.EncodeToString(sum[:]) != f.challenge {
			t.Errorf("PKCE verifier does not match the challenge")
		}
		json.NewEncoder(w).Encode(map[string]any{
			"access_token": "OATK-123",
			"token_type":   "bearer",
			"scope":        "profile https://identity.mozilla.com/apps/vpn",
		})
	})

	f.authSrv = httptest.NewServer(authMux)
	f.oauthSrv = httptest.NewServer(oauthMux)
	t.Cleanup(func() {
		f.authSrv.Close()
		f.oauthSrv.Close()
	})
	return f
}

func TestLoginAndOAuthFlow(t *testing.T) {
	for _, tc := range []struct {
		name          string
		stretchVer    string
		wantAuthPW    string
		sessionVerify bool
	}{
		{"v1-account", "v1", vecAuthPW1, true},
		{"v2-account", "v2", vecAuthPW2, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFakeFxA(t, tc.sessionVerify, tc.stretchVer)
			client := NewClient(f.authSrv.URL)
			session, err := client.Login(vecEmail, vecPassword, "")
			if err != nil {
				t.Fatal(err)
			}
			f.mu.Lock()
			gotPW := f.lastAuthPW
			f.mu.Unlock()
			if gotPW != tc.wantAuthPW {
				t.Fatalf("server saw authPW = %s, want %s", gotPW, tc.wantAuthPW)
			}

			if _, err := client.SessionStatus(session); err != nil {
				t.Fatalf("SessionStatus: %v", err)
			}

			oauth := NewOAuthClient(f.oauthSrv.URL, "5882386c6d801776")
			tok, err := oauth.TokenForSession(session, []string{"profile", "https://identity.mozilla.com/apps/vpn"})
			if err != nil {
				t.Fatal(err)
			}
			if tok != "OATK-123" {
				t.Fatalf("got access token %q", tok)
			}
		})
	}
}

func TestTOTPLogin(t *testing.T) {
	f := newFakeFxA(t, false, "v1")
	client := NewClient(f.authSrv.URL)
	session, err := client.Login(vecEmail, vecPassword, "")
	if err != nil {
		t.Fatal(err)
	}
	if err := client.VerifyTOTP(session, "123456"); err != nil {
		t.Fatalf("VerifyTOTP: %v", err)
	}
	f.mu.Lock()
	code := f.totpCode
	f.mu.Unlock()
	if code != "123456" {
		t.Fatalf("server saw TOTP code %q", code)
	}
}
