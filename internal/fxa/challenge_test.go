package fxa

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

const (
	fakePrefix   = "/_fs-ch-TEST"
	fakeCookie   = "fs-ch-test"
	fakePowBase  = "challenge-base"
	fakeSuffix   = "q7"
	fakePostBack = `{"status":"success"}`
)

// fakeEdge answers like the Fastly layer in front of the auth server: every
// request is blocked with a bare 406 until the client challenge has been
// solved and its cookie sent back.
func fakeEdge(t *testing.T, blocked *atomic.Int32) *httptest.Server {
	t.Helper()
	target := sha256.Sum256([]byte(fakePowBase + fakeSuffix))

	mux := http.NewServeMux()
	mux.HandleFunc("/account/login", func(w http.ResponseWriter, r *http.Request) {
		if cookie, err := r.Cookie(fakeCookie); err != nil || cookie.Value != "granted" {
			blocked.Add(1)
			w.WriteHeader(http.StatusNotAcceptable)
			return
		}
		json.NewEncoder(w).Encode(map[string]any{
			"uid":          "abcd1234abcd1234",
			"sessionToken": fakeSessionToken,
			"verified":     true,
		})
	})
	mux.HandleFunc("/oauth/authorization", func(w http.ResponseWriter, r *http.Request) {
		if cookie, err := r.Cookie(fakeCookie); err != nil || cookie.Value != "granted" {
			blocked.Add(1)
			w.WriteHeader(http.StatusNotAcceptable)
			return
		}
		var body map[string]string
		json.NewDecoder(r.Body).Decode(&body)
		json.NewEncoder(w).Encode(map[string]any{
			"redirect": "https://redirect.example/oauth/success?code=fake-code&state=" + body["state"],
		})
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		if cookie, err := r.Cookie(fakeCookie); err != nil || cookie.Value != "granted" {
			blocked.Add(1)
			w.WriteHeader(http.StatusNotAcceptable)
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"access_token": "fake-oat"})
	})
	mux.HandleFunc(fakePrefix+"/script.js", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/javascript")
		w.Write([]byte(`(function(){init([{"ty":"pow","data":{"base":"` + fakePowBase +
			`","hash":"` + hex.EncodeToString(target[:]) +
			`","hmac":"h","expires":4102444800}}], "tok-1", "` + fakePrefix + `");})()`))
	})
	mux.HandleFunc(fakePrefix+"/fst-post-back", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Token string `json:"token"`
			Data  []struct {
				Ty     string `json:"ty"`
				Answer string `json:"answer"`
				Base   string `json:"base"`
			} `json:"data"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Errorf("post-back body: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if req.Token != "tok-1" || len(req.Data) != 1 ||
			req.Data[0].Ty != "pow" || req.Data[0].Base != fakePowBase || req.Data[0].Answer != fakeSuffix {
			t.Errorf("post-back answered pow wrongly: %+v", req)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		http.SetCookie(w, &http.Cookie{Name: fakeCookie, Value: "granted", Path: "/"})
		w.Write([]byte(fakePostBack))
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if cookie, err := r.Cookie(fakeCookie); err == nil && cookie.Value == "granted" {
			w.Write([]byte("<html>Firefox Accounts</html>"))
			return
		}
		w.Write([]byte("<html><title>Client Challenge</title><script src=\"" + fakePrefix + "/script.js\"></script></html>"))
	})
	return httptest.NewServer(mux)
}

const fakeSessionToken = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

// A 406 from the edge is not a refusal of the request: the challenge has to be
// solved and the same request sent again, which is what makes sign-in work at
// all for a non-browser client.
func TestCallSolvesChallengeAndRetries(t *testing.T) {
	var blocked atomic.Int32
	srv := fakeEdge(t, &blocked)
	defer srv.Close()

	// Keep the solver on the fake edge: it would otherwise ask the real
	// account site for a challenge page when the API host has none.
	restoreSite := fastlySiteBase
	fastlySiteBase = srv.URL
	t.Cleanup(func() { fastlySiteBase = restoreSite })

	c := NewClient(srv.URL)
	c.Logf = func(string, ...any) {}

	var session Session
	if err := c.call("POST", "/account/login", map[string]string{"email": "user@example.com"}, "", &session); err != nil {
		t.Fatalf("call through the fake edge: %v", err)
	}
	if session.Token != fakeSessionToken {
		t.Fatalf("login returned session %+v", session)
	}
	if got := blocked.Load(); got != 1 {
		t.Errorf("edge blocked %d requests, want one before the challenge was solved", got)
	}
}

// The OAuth server sits behind the same edge, so its POSTs are blocked the
// same way; the OAuth client carries its own jar and 406 retry loop.
func TestOAuthSolvesChallengeAndRetries(t *testing.T) {
	var blocked atomic.Int32
	srv := fakeEdge(t, &blocked)
	defer srv.Close()

	restoreSite := fastlySiteBase
	fastlySiteBase = srv.URL
	t.Cleanup(func() { fastlySiteBase = restoreSite })

	c := NewOAuthClient(srv.URL, "5882386c6d801776")
	c.Logf = func(string, ...any) {}

	access, err := c.TokenForSession(&Session{Token: fakeSessionToken, Verified: true}, []string{"profile"})
	if err != nil {
		t.Fatalf("token through the fake edge: %v", err)
	}
	if access != "fake-oat" {
		t.Fatalf("token exchange returned %q", access)
	}
	if got := blocked.Load(); got != 1 {
		t.Errorf("edge blocked %d requests, want one before the challenge was solved", got)
	}
}

// Without a solvable challenge the failure stays a 406 so callers can still
// report what the edge did.
func TestCallReportsUnsolvedChallenge(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotAcceptable)
	}))
	defer srv.Close()

	// Keep the solver on the fake edge: it would otherwise ask the real
	// account site for a challenge page.
	restoreSite := fastlySiteBase
	fastlySiteBase = srv.URL
	t.Cleanup(func() { fastlySiteBase = restoreSite })

	c := NewClient(srv.URL)
	c.Logf = func(string, ...any) {}

	err := c.call("GET", "/session/status", nil, "Bearer x", nil)
	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr.Status != http.StatusNotAcceptable {
		t.Fatalf("want APIError 406, got %v", err)
	}
	if !strings.Contains(apiErr.Message, "challenge") {
		t.Errorf("406 failure should explain the challenge, got %q", apiErr.Message)
	}
}

func TestParseChallengeInit(t *testing.T) {
	script := `init([{"ty":"pat","data":{}}], "tok-9", "/_fs-ch-ABC");`
	challenges, token, err := parseChallengeInit(script)
	if err != nil {
		t.Fatal(err)
	}
	if token != "tok-9" || len(challenges) != 1 || challenges[0].Ty != "pat" {
		t.Fatalf("parsed %+v token %q", challenges, token)
	}
}

func TestSolvePowRejectsBadTargets(t *testing.T) {
	if _, ok := solvePow(fakePowBase, "not-hex"); ok {
		t.Error("non-hex target solved")
	}
	if _, ok := solvePow(fakePowBase, hex.EncodeToString([]byte("too-short"))); ok {
		t.Error("short target solved")
	}
}
