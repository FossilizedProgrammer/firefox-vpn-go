package fxa

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// Fastly's edge in front of api.accounts.firefox.com rejects the requests
// Mozilla considers non-browser with a bare HTTP 406 (empty body, no FxA
// error payload). The check is cleared by solving the JavaScript "client
// challenge" the edge serves on the account site and sending back the cookie
// it issues: the cookie is set for Domain=firefox.com, so it also covers the
// API host.
const (
	// fastlySolverUA is what the challenge page runs in: the edge profiles
	// the fingerprint of the client that solves, not the one that calls the
	// API afterwards.
	fastlySolverUA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36"

	// maxChallengeAttempts bounds how often one API call re-solves the
	// challenge; each attempt costs a full solve.
	maxChallengeAttempts = 3

	// maxPostBackRounds caps the follow-up challenge rounds, because Fastly
	// issues a new task (or a new CAPTCHA image) after a wrong answer.
	maxPostBackRounds = 8

	// challengeTimeout bounds a whole solve: page, script, answers, post-back
	// and the probe that proves the cookie works.
	challengeTimeout = 60 * time.Second
)

var (
	// fastlySiteBase serves the challenge page; the API host itself usually
	// answers the empty 406 even to the solver. It is a var so tests can
	// point the solver at a fake edge instead of the real one.
	fastlySiteBase = "https://accounts.firefox.com"

	fastlyPrefixRe = regexp.MustCompile(`/_fs-ch-[A-Za-z0-9]+`)
	fastlyInitRe   = regexp.MustCompile(`init\((\[[^\]]*\]),\s*"([^"]+)",\s*"([^"]+)"`)

	// powAlphabet is the character set the challenge script brute-forces;
	// the answer is a two-character suffix, so the search space is 62*62.
	powAlphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

	// errNoChallengePage means the host served regular content instead of a
	// challenge page, so no cookie can be earned there.
	errNoChallengePage = errors.New("host did not serve a Fastly challenge page")
)

type fastlyChallenge struct {
	Ty   string          `json:"ty"`
	Data json.RawMessage `json:"data"`
}

type fastlyPowData struct {
	Base string `json:"base"`
	Hash string `json:"hash"`
	HMAC string `json:"hmac"`
	// Expires is kept as raw JSON and echoed back unchanged: it works
	// whichever way the edge spells it.
	Expires json.RawMessage `json:"expires"`
}

type fastlyPostBack struct {
	Token string `json:"token"`
	Data  []any  `json:"data"`
}

type fastlyPostBackResponse struct {
	Status string            `json:"status"`
	Ch     []fastlyChallenge `json:"ch"`
	Tok    string            `json:"tok"`
}

// solveChallenge earns the anti-bot cookie and puts it in jar so the next API
// request passes the edge. It is shared by the auth and the OAuth client, each
// of which holds its own jar. Each host is solved with a throw-away client
// holding a fresh jar: a client that already has a valid cookie is served the
// real page instead of the challenge, which would leave nothing to solve.
func solveChallenge(transport http.RoundTripper, jar *cookiejar.Jar, apiOrigin string, logf func(format string, args ...any)) error {
	solverLogf := func(format string, args ...any) {
		if logf != nil {
			logf(format, args...)
			return
		}
		log.Printf(format, args...)
	}

	var lastErr error
	for _, base := range []string{apiOrigin, fastlySiteBase} {
		if base == "" {
			continue
		}
		err := solveOnHost(transport, jar, apiOrigin, base, solverLogf)
		if err == nil {
			return nil
		}
		lastErr = err
	}
	if lastErr == nil {
		lastErr = errNoChallengePage
	}
	return lastErr
}

// originOf is the scheme://host part of a base URL, which is what the edge and
// the challenge page are fetched from.
func originOf(baseURL string) string {
	u, err := url.Parse(baseURL)
	if err != nil || u.Host == "" {
		return ""
	}
	return u.Scheme + "://" + u.Host
}

func solveOnHost(transport http.RoundTripper, jar *cookiejar.Jar, apiOrigin, base string, logf func(format string, args ...any)) error {
	solveJar, err := cookiejar.New(nil)
	if err != nil {
		return err
	}
	client := &http.Client{Transport: transport, Jar: solveJar, Timeout: challengeTimeout}
	pageURL := base + "/"

	page, isChallenge, err := fetchChallengePage(client, pageURL)
	if err != nil {
		return err
	}
	if !isChallenge {
		return errNoChallengePage
	}

	prefix := fastlyPrefixRe.FindString(page)
	if prefix == "" {
		return fmt.Errorf("challenge asset prefix not found on %s", strings.TrimPrefix(base, "https://"))
	}
	script, err := fetchText(client, base+prefix+"/script.js?reload=true")
	if err != nil {
		return fmt.Errorf("fetching challenge script: %w", err)
	}
	challenges, token, err := parseChallengeInit(script)
	if err != nil {
		return err
	}

	var kinds []string
	for round := 0; round < maxPostBackRounds; round++ {
		answers := make([]any, 0, len(challenges))
		for _, ch := range challenges {
			kinds = append(kinds, ch.Ty)
			answer, err := answerChallenge(client, base+prefix, token, ch)
			if err != nil {
				return err
			}
			answers = append(answers, answer)
		}

		pbResp, data, err := postBack(client, base, prefix, token, answers)
		if err != nil {
			return err
		}
		if pbResp.Status == "success" {
			// Probe before installing: the cookie is bound to the exit IP that
			// solved it, so a proxy that rotated between solve and probe would
			// otherwise be discovered by the API call itself.
			_, stillChallenged, err := fetchChallengePage(client, pageURL)
			if err != nil {
				return err
			}
			if stillChallenged {
				return errors.New("challenge cookie not accepted on this exit IP")
			}
			if err := installChallengeCookies(jar, solveJar, pageURL, apiOrigin); err != nil {
				return err
			}
			logf("Fastly challenge solved host=%s challenges=%s rounds=%d",
				strings.TrimPrefix(base, "https://"), strings.Join(kinds, ","), round+1)
			return nil
		}
		if len(pbResp.Ch) == 0 || pbResp.Tok == "" {
			return fmt.Errorf("unexpected post-back response: %s", snippet(data))
		}
		challenges, token = pbResp.Ch, pbResp.Tok
	}
	return fmt.Errorf("Fastly challenge did not complete within %d rounds", maxPostBackRounds)
}

func postBack(client *http.Client, base, prefix, token string, answers []any) (*fastlyPostBackResponse, []byte, error) {
	body, err := json.Marshal(fastlyPostBack{Token: token, Data: answers})
	if err != nil {
		return nil, nil, err
	}
	req, err := http.NewRequest(http.MethodPost, base+prefix+"/fst-post-back", bytes.NewReader(body))
	if err != nil {
		return nil, nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", fastlySolverUA)
	req.Header.Set("Origin", baseOrigin(base+prefix))

	resp, err := client.Do(req)
	if err != nil {
		return nil, nil, fmt.Errorf("challenge post-back: %w", err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, data, fmt.Errorf("challenge post-back returned HTTP %d: %s", resp.StatusCode, snippet(data))
	}
	var out fastlyPostBackResponse
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, data, fmt.Errorf("parsing post-back response: %w", err)
	}
	return &out, data, nil
}

// fetchChallengePage reports whether URL answers with a Fastly challenge page.
func fetchChallengePage(client *http.Client, pageURL string) (string, bool, error) {
	body, err := fetchText(client, pageURL)
	if err != nil {
		return "", false, err
	}
	return body, strings.Contains(body, "/_fs-ch-") && strings.Contains(body, "Client Challenge"), nil
}

func fetchText(client *http.Client, rawURL string) (string, error) {
	req, err := http.NewRequest(http.MethodGet, rawURL, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", fastlySolverUA)
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")

	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("GET %s: %w", rawURL, err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	if err != nil {
		return "", err
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("GET %s returned HTTP %d", rawURL, resp.StatusCode)
	}
	return string(data), nil
}

// parseChallengeInit extracts the challenge list and token from the trailing
// init([...], "token", "prefix", ...) call of the challenge script.
func parseChallengeInit(script string) ([]fastlyChallenge, string, error) {
	matches := fastlyInitRe.FindAllStringSubmatch(script, -1)
	if len(matches) == 0 {
		return nil, "", errors.New("challenge init call not found in script")
	}
	m := matches[len(matches)-1]

	var challenges []fastlyChallenge
	if err := json.Unmarshal([]byte(m[1]), &challenges); err != nil {
		return nil, "", fmt.Errorf("parsing challenge list: %w", err)
	}
	if len(challenges) == 0 {
		return nil, "", errors.New("empty challenge list")
	}
	return challenges, m[2], nil
}

// answerChallenge builds the fst-post-back answer for one challenge task.
func answerChallenge(client *http.Client, prefixURL, token string, ch fastlyChallenge) (any, error) {
	switch ch.Ty {
	case "pow":
		var d fastlyPowData
		if err := json.Unmarshal(ch.Data, &d); err != nil {
			return nil, fmt.Errorf("parsing pow challenge: %w", err)
		}
		answer, ok := solvePow(d.Base, d.Hash)
		if !ok {
			return nil, fmt.Errorf("no proof-of-work solution found for base %q", d.Base)
		}
		return map[string]any{
			"ty":      "pow",
			"base":    d.Base,
			"answer":  answer,
			"hmac":    d.HMAC,
			"expires": d.Expires,
		}, nil

	case "pat":
		auth, err := fetchPAT(client, prefixURL, token)
		if err != nil {
			return nil, err
		}
		return map[string]any{"ty": "pat", "auth": auth}, nil

	case "clientmetrics":
		return clientMetricsAnswer(), nil

	case "captcha":
		// An image CAPTCHA needs a person; the CLI cannot answer it. Sign in
		// once from Firefox and use --session-token instead.
		return nil, errors.New("Fastly requires an image CAPTCHA answer; sign in from Firefox and pass its sessionToken")

	default:
		return nil, fmt.Errorf("unsupported Fastly challenge type %q", ch.Ty)
	}
}

// solvePow brute-forces the two-character suffix that makes
// SHA256(base+suffix) equal the target hash.
func solvePow(base, targetHex string) (string, bool) {
	target, err := hex.DecodeString(targetHex)
	if err != nil || len(target) != sha256.Size {
		return "", false
	}
	buf := make([]byte, len(base)+2)
	copy(buf, base)
	for i := 0; i < len(powAlphabet); i++ {
		buf[len(base)] = powAlphabet[i]
		for j := 0; j < len(powAlphabet); j++ {
			buf[len(base)+1] = powAlphabet[j]
			sum := sha256.Sum256(buf)
			if bytes.Equal(sum[:], target) {
				return string(buf[len(base):]), true
			}
		}
	}
	return "", false
}

// fetchPAT asks for the Private Access Token a "pat" challenge wants. A 401
// or 400 means this client cannot mint one (a browser-only feature); posting
// back an empty auth is what the challenge script does, and Fastly then falls
// back to a solvable challenge.
func fetchPAT(client *http.Client, prefixURL, token string) (string, error) {
	u := prefixURL + "/pat?token=" + url.QueryEscape(token)
	req, err := http.NewRequest(http.MethodPost, u, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Accept", "text/plain")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", fastlySolverUA)
	req.Header.Set("Origin", baseOrigin(prefixURL))

	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("PAT request: %w", err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", err
	}
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusBadRequest {
		return "", nil
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("PAT request returned HTTP %d: %s", resp.StatusCode, snippet(data))
	}
	var out struct {
		Auth string `json:"auth"`
	}
	if err := json.Unmarshal(data, &out); err != nil {
		return "", fmt.Errorf("parsing PAT response: %w", err)
	}
	if out.Auth == "" {
		return "", errors.New("empty PAT auth token")
	}
	return out.Auth, nil
}

// clientMetricsAnswer fabricates a benign browser-metrics payload; Mozilla's
// configuration issues PAT/PoW tasks, so this is a best-effort fallback.
func clientMetricsAnswer() map[string]any {
	return map[string]any{
		"ty":                   "clientmetrics",
		"webdriver":            false,
		"bot_detection_result": map[string]any{"bot_detected": false, "bot_kind": nil},
		"browser_metrics":      map[string]any{"client_data": "{}", "error_trace": nil},
		"detector_results":     map[string]any{},
		"v":                    2,
	}
}

// installChallengeCookies copies the cookies the solver earned (src) into the
// API client's jar (dst) for both the API host and the site host, so the retry
// carries them wherever the edge looks for them.
func installChallengeCookies(dst, src *cookiejar.Jar, pageURL, apiOrigin string) error {
	parsed, err := url.Parse(pageURL)
	if err != nil {
		return err
	}
	cookies := src.Cookies(parsed)
	if len(cookies) == 0 {
		return errors.New("challenge completed but no cookies were issued")
	}
	for _, raw := range []string{apiOrigin, fastlySiteBase} {
		if raw == "" {
			continue
		}
		u, err := url.Parse(raw)
		if err != nil || u.Host == "" {
			continue
		}
		dst.SetCookies(u, cookies)
	}
	return nil
}

// baseOrigin derives the Origin header value for challenge requests from a
// "/_fs-ch-..." prefixed URL.
func baseOrigin(prefixURL string) string {
	if idx := strings.Index(prefixURL, "/_fs-ch-"); idx > 0 {
		return prefixURL[:idx]
	}
	return prefixURL
}

func snippet(b []byte) string {
	s := strings.TrimSpace(string(b))
	if len(s) > 200 {
		return s[:200] + "..."
	}
	return s
}
