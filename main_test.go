package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

// --- fakes --------------------------------------------------------------

type countingGuardian struct {
	mu     sync.Mutex
	serial int
	issued []string
}

func (g *countingGuardian) issuedToken(i int) string {
	g.mu.Lock()
	defer g.mu.Unlock()
	if i < len(g.issued) {
		return g.issued[i]
	}
	return ""
}

func (g *countingGuardian) count() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.serial
}

func (g *countingGuardian) jwt() string {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.serial++
	exp := time.Now().Add(122 * time.Second).Unix() // rotates ~2s from now
	nbf := time.Now().Add(-5 * time.Second).Unix()
	seg := func(v any) string {
		b, _ := json.Marshal(v)
		return base64.RawURLEncoding.EncodeToString(b)
	}
	tok := seg(map[string]string{"alg": "RS256", "typ": "JWT"}) + "." +
		seg(map[string]any{"sub": "u", "aud": "a", "iat": nbf, "nbf": nbf, "exp": exp, "iss": "t"}) +
		"." + seg(fmt.Sprintf("sig-%d", g.serial))
	g.issued = append(g.issued, tok)
	return tok
}

func fakeEdge(t *testing.T, seen *syncMock) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "edge.test"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames: []string{"edge.test"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	inner, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { inner.Close() })
	l := tls.NewListener(inner, &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}})
	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				br := bufio.NewReader(conn)
				if _, err := br.ReadString('\n'); err != nil {
					return
				}
				var auth string
				for {
					line, err := br.ReadString('\n')
					if err != nil || line == "\r\n" {
						break
					}
					if strings.HasPrefix(strings.ToLower(line), "proxy-authorization:") {
						auth = strings.TrimSpace(line[len("proxy-authorization:"):])
					}
				}
				seen.add(auth)
				// Real JWTs start with the base64 of the JSON header ("eyJ…").
				if !strings.HasPrefix(auth, "Bearer eyJ") {
					conn.Write([]byte("HTTP/1.1 403 Forbidden\r\n\r\n"))
					return
				}
				conn.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n"))
				io.Copy(conn, br)
			}()
		}
	}()
	return l.Addr().String()
}

type syncMock struct {
	mu    sync.Mutex
	items []string
}

func (s *syncMock) add(v string) {
	s.mu.Lock()
	s.items = append(s.items, v)
	s.mu.Unlock()
}

func (s *syncMock) snapshot() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.items...)
}

func freePort(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().String()
}

// --- the end-to-end test ------------------------------------------------

func TestFullBinaryFlow(t *testing.T) {
	var seen syncMock
	edge := fakeEdge(t, &seen)

	authMux := http.NewServeMux()
	authMux.HandleFunc("/session/status", func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer fxs_") {
			t.Errorf("auth: bad session header %q", r.Header.Get("Authorization"))
		}
		json.NewEncoder(w).Encode(map[string]string{"uid": "abcdef1234567890"})
	})
	authSrv := httptest.NewServer(authMux)
	defer authSrv.Close()

	oauthMux := http.NewServeMux()
	oauthMux.HandleFunc("/oauth/authorization", func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		json.NewDecoder(r.Body).Decode(&body)
		state, _ := body["state"].(string)
		json.NewEncoder(w).Encode(map[string]string{
			"redirect": "https://x.example/?code=C&state=" + state,
		})
	})
	oauthMux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"access_token": "OATK", "token_type": "bearer"})
	})
	oauthSrv := httptest.NewServer(oauthMux)
	defer oauthSrv.Close()

	g := &countingGuardian{}
	guardianMux := http.NewServeMux()
	guardianMux.HandleFunc("/api/v1/fpn/activate", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"subscribed": true, "uid": 7, "maxBytes": "1073741824", "limited_bandwidth": true,
		})
	})
	guardianMux.HandleFunc("/api/v1/fpn/token", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Quota-Limit", "1073741824")
		w.Header().Set("X-Quota-Remaining", "1073740000")
		w.Header().Set("X-Quota-Reset", time.Now().Add(24*time.Hour).UTC().Format(time.RFC3339))
		json.NewEncoder(w).Encode(map[string]string{"token": g.jwt()})
	})
	guardianSrv := httptest.NewServer(guardianMux)
	defer guardianSrv.Close()

	socksAddr := freePort(t)
	opts := &options{
		sessionToken:       "0f1e2d3c4b5a69788796a5b4c3d2e1f00f1e2d3c4b5a69788796a5b4c3d2e1f0",
		authServer:         authSrv.URL,
		oauthServer:        oauthSrv.URL,
		guardianURL:        guardianSrv.URL,
		serverOverride:     edge,
		socksAddr:          socksAddr,
		verbose:            true,
		insecureSkipVerify: true,
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errCh := make(chan error, 1)
	go func() { errCh <- run(ctx, opts) }()

	// Wait for the SOCKS5 listener to come up.
	var conn net.Conn
	deadline := time.Now().Add(5 * time.Second)
	for {
		var err error
		conn, err = net.DialTimeout("tcp", socksAddr, time.Second)
		if err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("socks listener never came up: %v", err)
		}
		time.Sleep(50 * time.Millisecond)
	}
	conn.Close()

	// First connection must ride the first pass.
	roundTripViaSocks(t, socksAddr, "example.org:443")

	// Wait for the rotation loop to fetch pass #2, then connect again and
	// confirm the edge saw the new token.
	waitFor(t, 10*time.Second, func() bool {
		return g.count() >= 2
	})
	roundTripViaSocks(t, socksAddr, "example.org:443")

	wantSecondAuth := "Bearer " + g.issuedToken(1)
	waitFor(t, 5*time.Second, func() bool {
		for _, a := range seen.snapshot() {
			if a == wantSecondAuth {
				return true
			}
		}
		return false
	})

	cancel()
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("run() returned error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("run() did not exit after cancel")
	}
}

func TestUsageOnly(t *testing.T) {
	authSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]string{"uid": "abcdef1234567890"})
	}))
	defer authSrv.Close()

	oauthMux := http.NewServeMux()
	oauthMux.HandleFunc("/oauth/authorization", func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		json.NewDecoder(r.Body).Decode(&body)
		state, _ := body["state"].(string)
		json.NewEncoder(w).Encode(map[string]string{
			"redirect": "https://x.example/?code=C&state=" + state,
		})
	})
	oauthMux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"access_token": "OATK", "token_type": "bearer"})
	})
	oauthSrv := httptest.NewServer(oauthMux)
	defer oauthSrv.Close()

	g := &countingGuardian{}
	guardianMux := http.NewServeMux()
	guardianMux.HandleFunc("/api/v1/fpn/activate", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"subscribed": true, "uid": 7, "maxBytes": "1073741824", "limited_bandwidth": true,
		})
	})
	guardianMux.HandleFunc("/api/v1/fpn/token", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Quota-Limit", "1073741824")
		w.Header().Set("X-Quota-Remaining", "536870912")
		w.Header().Set("X-Quota-Reset", time.Now().Add(24*time.Hour).UTC().Format(time.RFC3339))
		json.NewEncoder(w).Encode(map[string]string{"token": g.jwt()})
	})
	guardianSrv := httptest.NewServer(guardianMux)
	defer guardianSrv.Close()

	opts := &options{
		sessionToken: "0f1e2d3c4b5a69788796a5b4c3d2e1f00f1e2d3c4b5a69788796a5b4c3d2e1f0",
		authServer:   authSrv.URL,
		oauthServer:  oauthSrv.URL,
		guardianURL:  guardianSrv.URL,
		usageOnly:    true,
	}
	// A usage check must not touch the server-list endpoint, so this runs
	// fully offline against the fakes above.
	if err := run(context.Background(), opts); err != nil {
		t.Fatalf("run() with usageOnly returned error: %v", err)
	}
	if g.count() != 1 {
		t.Fatalf("token endpoint hit %d times, want 1", g.count())
	}
}

// fakeServerList spins up a fake Remote Settings endpoint with three
// countries: US (locked, 1 usable + 1 quarantined server), CA (unlocked,
// 1 usable server), BR (locked, only a quarantined server). Returns its URL.
func fakeServerList(t *testing.T) string {
	t.Helper()
	rsMux := http.NewServeMux()
	rsMux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"data": []any{
			map[string]any{
				"code": "US", "name": "United States", "locked": true,
				"cities": []any{map[string]any{
					"code": "nyc", "name": "New York",
					"servers": []any{
						map[string]any{"hostname": "a.example", "port": 443},
						map[string]any{"hostname": "b.example", "port": 443, "quarantined": true},
					},
				}},
			},
			map[string]any{
				"code": "CA", "name": "Canada",
				"cities": []any{map[string]any{
					"code": "yyz", "name": "Toronto",
					"servers": []any{map[string]any{"hostname": "c.example", "port": 443}},
				}},
			},
			map[string]any{
				"code": "BR", "name": "Brazil", "locked": true,
				"cities": []any{map[string]any{
					"code": "gru", "name": "São Paulo",
					"servers": []any{map[string]any{"hostname": "d.example", "port": 443, "quarantined": true}},
				}},
			},
		}})
	})
	rs := httptest.NewServer(rsMux)
	t.Cleanup(rs.Close)
	return rs.URL
}

// captureLog redirects the standard logger into a buffer for the test.
func captureLog(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })
	return &buf
}

func TestListCountries(t *testing.T) {
	rs := fakeServerList(t)
	buf := captureLog(t)

	opts := &options{remoteSettings: rs, listCountries: true}
	// No auth flags: listing must not require an FxA session.
	if err := run(context.Background(), opts); err != nil {
		t.Fatalf("run() with listCountries returned error: %v", err)
	}
	out := buf.String()
	for _, want := range []string{
		"US", "United States", "1 server, 1 city (locked)",
		"CA", "Canada", "1 server, 1 city",
		"BR", "Brazil", "0 servers, 0 cities (locked)",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q:\n%s", want, out)
		}
	}
}

func TestListCountriesFreeOnly(t *testing.T) {
	rs := fakeServerList(t)
	buf := captureLog(t)

	opts := &options{remoteSettings: rs, listCountries: true, freeOnly: true}
	if err := run(context.Background(), opts); err != nil {
		t.Fatalf("run() with listCountries+freeOnly returned error: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "Canada") || !strings.Contains(out, "1 server, 1 city") {
		t.Errorf("free listing missing unlocked Canada:\n%s", out)
	}
	for _, unwanted := range []string{"United States", "Brazil", "(locked)"} {
		if strings.Contains(out, unwanted) {
			t.Errorf("free listing should hide %q:\n%s", unwanted, out)
		}
	}
}

func TestListenerFlagCombos(t *testing.T) {
	cases := []struct {
		name  string
		args  string
		socks string // effective socks addr after the default resolution
	}{
		{"neither", "", "127.0.0.1:1080"},
		{"socks only", "--socks 127.0.0.1:2080", "127.0.0.1:2080"},
		{"http only", "--http 127.0.0.1:9088", ""},
		{"both", "--socks 127.0.0.1:2080 --http 127.0.0.1:9088", "127.0.0.1:2080"},
		{"socks explicitly empty", "--socks= --http 127.0.0.1:9088", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fs := flag.NewFlagSet("t", flag.ContinueOnError)
			var socks, httpAddr string
			fs.StringVar(&socks, "socks", "127.0.0.1:1080", "")
			fs.StringVar(&httpAddr, "http", "", "")
			var args []string
			if tc.args != "" {
				args = strings.Fields(tc.args)
			}
			if err := fs.Parse(args); err != nil {
				t.Fatal(err)
			}
			chosen := map[string]bool{}
			fs.Visit(func(f *flag.Flag) { chosen[f.Name] = true })
			if httpInsteadOfSocks(chosen) {
				socks = ""
			}
			if socks != tc.socks {
				t.Errorf("effective socks addr %q, want %q (http=%q)", socks, tc.socks, httpAddr)
			}
		})
	}
}

func roundTripViaSocks(t *testing.T, proxyAddr, target string) {
	t.Helper()
	conn, err := net.DialTimeout("tcp", proxyAddr, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		t.Fatal(err)
	}
	greet := make([]byte, 2)
	if _, err := io.ReadFull(conn, greet); err != nil {
		t.Fatal(err)
	}
	host, portStr, _ := net.SplitHostPort(target)
	var port uint16
	fmt.Sscanf(portStr, "%d", &port)
	req := []byte{0x05, 0x01, 0x00, 0x03, byte(len(host))}
	req = append(req, host...)
	var pb [2]byte
	binary.BigEndian.PutUint16(pb[:], port)
	req = append(req, pb[:]...)
	if _, err := conn.Write(req); err != nil {
		t.Fatal(err)
	}
	reply := make([]byte, 10)
	if _, err := io.ReadFull(conn, reply); err != nil {
		t.Fatal(err)
	}
	if reply[1] != 0x00 {
		t.Fatalf("socks CONNECT refused: %d", reply[1])
	}
	msg := []byte("ping")
	if _, err := conn.Write(msg); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(msg))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatal(err)
	}
	if string(got) != string(msg) {
		t.Fatalf("echo mismatch: %q", got)
	}
}

func waitFor(t *testing.T, d time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("condition not met in time")
}
