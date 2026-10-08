// ffvpn is a standalone Go client for the Firefox browser's built-in VPN
// (the "IP Protection" proxy, powered by Mozilla VPN/Guardian).
//
// It signs in with a Firefox Account, activates the Guardian proxy service,
// fetches short-lived JWT proxy passes, and exposes the tunnel as a local
// SOCKS5 / HTTP CONNECT proxy. Requires a Firefox Account that Guardian
// considers entitled (a Mozilla VPN subscription) and a supported region —
// both are enforced server-side.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"ffvpn/internal/fxa"
	"ffvpn/internal/guardian"
	"ffvpn/internal/localproxy"
	"ffvpn/internal/servers"
	"ffvpn/internal/tunnel"
)

const (
	defaultAuthServer  = "https://api.accounts.firefox.com/v1"
	defaultOAuthServer = "https://oauth.accounts.firefox.com/v1"
	// The shipped Firefox default of browser.ipProtection.guardian.endpoint;
	// note .org — the JS fallback (.com) does not even resolve.
	defaultGuardian     = "https://vpn.mozilla.org"
	firefoxDesktopCID   = "5882386c6d801776"
	vpnScope            = "https://identity.mozilla.com/apps/vpn"
	remoteSettingsProxy = "https://firefox.settings.services.mozilla.com/v1/buckets/main/collections/vpn-serverlist/records"
)

type options struct {
	sessionToken   string
	email          string
	password       string
	unblockCode    string
	clientID       string
	authServer     string
	oauthServer    string
	guardianURL    string
	remoteSettings string
	socksAddr      string
	httpAddr       string
	country        string
	serverOverride string
	dialProxy      string
	sni            string
	usageOnly      bool
	listCountries  bool
	freeOnly       bool
	verbose        bool
	// insecureSkipVerify is a test hook for self-signed lab edges; it is
	// intentionally not exposed as a CLI flag.
	insecureSkipVerify bool
}

func main() {
	log.SetFlags(log.Ltime)
	var opts options
	flag.StringVar(&opts.sessionToken, "session-token", "", "FxA session token (64 hex chars); takes priority over other auth")
	flag.StringVar(&opts.email, "email", "", "Firefox Account email (interactive login)")
	flag.StringVar(&opts.password, "password", "", "Password (use env FFVPN_PASSWORD or stdin to avoid shell history)")
	flag.StringVar(&opts.unblockCode, "unblock-code", "", "FxA login unblock code, if the sign-in was blocked")
	flag.StringVar(&opts.clientID, "client-id", firefoxDesktopCID, "FxA OAuth client_id")
	flag.StringVar(&opts.authServer, "auth-server", defaultAuthServer, "FxA auth server base URL")
	flag.StringVar(&opts.oauthServer, "oauth-server", defaultOAuthServer, "FxA OAuth server base URL")
	flag.StringVar(&opts.guardianURL, "guardian", defaultGuardian, "Guardian API base URL")
	flag.StringVar(&opts.remoteSettings, "remote-settings", remoteSettingsProxy, "Remote Settings records URL for the server list")
	flag.StringVar(&opts.socksAddr, "socks", "127.0.0.1:1080", "local SOCKS5 listen address (empty to disable)")
	flag.StringVar(&opts.httpAddr, "http", "", "local HTTP CONNECT listen address (giving it alone replaces the default SOCKS listener)")
	flag.StringVar(&opts.country, "country", "", "exit country code (see --list-countries; default: recommended/anycast)")
	flag.StringVar(&opts.serverOverride, "server", "", "proxy edge override as host:port (skips server list)")
	flag.StringVar(&opts.dialProxy, "dial-proxy", "", "reach the edge via socks5://[user:pass@]host:port (bootstrap proxy)")
	flag.StringVar(&opts.sni, "sni", "", "TLS SNI sent to the proxy edge (default: the edge hostname; verified against the edge hostname)")
	flag.BoolVar(&opts.usageOnly, "usage", false, "print bandwidth quota usage and exit (no proxy listeners)")
	flag.BoolVar(&opts.listCountries, "list-countries", false, "print available exit countries and exit (no auth needed)")
	flag.BoolVar(&opts.freeOnly, "free-only", false, "with --list-countries, hide premium-locked countries")
	flag.BoolVar(&opts.verbose, "verbose", false, "verbose logging")
	flag.Parse()

	// --http without an explicit --socks means "HTTP instead of the default
	// SOCKS listener", not "in addition to it".
	chosen := map[string]bool{}
	flag.Visit(func(f *flag.Flag) { chosen[f.Name] = true })
	if httpInsteadOfSocks(chosen) {
		opts.socksAddr = ""
	}

	if err := run(context.Background(), &opts); err != nil {
		log.Fatalf("ffvpn: %v", err)
	}
}

// httpInsteadOfSocks reports whether the user picked an --http listener
// without naming --socks: --http then replaces the default SOCKS listener
// rather than adding to it.
func httpInsteadOfSocks(explicit map[string]bool) bool {
	return explicit["http"] && !explicit["socks"]
}

func run(ctx context.Context, opts *options) error {
	// Listing exit countries needs no FxA session: the server list is a
	// public Remote Settings collection.
	if opts.listCountries {
		fetcher := servers.NewFetcher()
		fetcher.URL = opts.remoteSettings
		list, err := fetcher.Fetch()
		if err != nil {
			return err
		}
		countries := list.Countries
		title := "Available exit countries (select with --country CODE):"
		if opts.freeOnly {
			countries = list.FreeCountries()
			title = "Free-tier exit countries, premium-locked ones hidden (select with --country CODE):"
		}
		printCountries(title, countries)
		return nil
	}
	if opts.freeOnly {
		return errors.New("--free-only only makes sense together with --list-countries")
	}

	// ---- 1. Establish an FxA session -------------------------------------
	session, err := resolveSession(opts)
	if err != nil {
		return err
	}
	authClient := fxa.NewClient(opts.authServer)
	uid, err := authClient.SessionStatus(session)
	if err != nil {
		return fmt.Errorf("session token rejected by auth server: %w", err)
	}
	uidPrefix := uid
	if len(uidPrefix) > 8 {
		uidPrefix = uidPrefix[:8]
	}
	log.Printf("FxA session OK (uid %s...)", uidPrefix)

	oauthClient := fxa.NewOAuthClient(opts.oauthServer, opts.clientID)
	getOAuthToken := func() (string, error) {
		return oauthClient.TokenForSession(session, []string{"profile", vpnScope})
	}

	// ---- 2. Activate Guardian and check entitlement ----------------------
	guardianClient := guardian.NewClient(opts.guardianURL)
	oauthToken, err := getOAuthToken()
	if err != nil {
		return fmt.Errorf("getting OAuth token: %w", err)
	}
	ent, _, err := guardianClient.Activate(oauthToken)
	if err != nil {
		return fmt.Errorf("activating proxy service: %w", err)
	}
	log.Printf("Entitlement: subscribed=%v uid=%d maxBytes=%s limitedBandwidth=%v",
		ent.Subscribed, ent.UID, ent.MaxBytes, ent.LimitedBandwidth)

	// ---- 3. Resolve a proxy edge (skipped for a usage-only check) --------
	hostPort := opts.serverOverride
	if hostPort == "" && !opts.usageOnly {
		fetcher := servers.NewFetcher()
		fetcher.URL = opts.remoteSettings
		list, err := fetcher.Fetch()
		if err != nil {
			return err
		}
		server, err := list.Pick(opts.country)
		if err != nil {
			return fmt.Errorf("%w (available: %s)", err, strings.Join(list.AvailableCountries(), ", "))
		}
		hostPort, err = server.ConnectHostPort()
		if err != nil {
			return err
		}
		log.Printf("Servers available in: %v", list.AvailableCountries())
	}
	if hostPort != "" {
		log.Printf("Using proxy edge: %s", hostPort)
	}

	// ---- 4. Fetch the first proxy pass -----------------------------------
	pass, usage, err := guardianClient.ProxyPass(oauthToken)
	if err != nil {
		return fmt.Errorf("fetching proxy pass: %w", err)
	}
	printUsage(usage)
	if opts.usageOnly {
		return nil
	}
	tokens := tunnel.NewAtomicToken(pass.Token)
	log.Printf("Proxy pass valid until %s", time.Unix(pass.Exp, 0).Format(time.RFC3339))

	// ---- 5. Serve local proxies ------------------------------------------
	dialer := &tunnel.Dialer{
		HostPort:           hostPort,
		ServerName:         opts.sni,
		Token:              tokens,
		DialThrough:        opts.dialProxy,
		InsecureSkipVerify: opts.insecureSkipVerify,
	}
	if opts.sni != "" {
		log.Printf("TLS SNI override: %s (edge %s)", opts.sni, hostPort)
	}
	if opts.dialProxy != "" {
		log.Printf("Dialing the edge through %s", tunnel.DescribeDialProxy(opts.dialProxy))
	}
	// If the caller provided no cancelable context, wire the process signal
	// handlers; tests pass their own context.
	if ctx.Done() == nil {
		var stop context.CancelFunc
		ctx, stop = signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
		defer stop()
	}

	// Rotation: refresh shortly before expiry; on 401-class failures the
	// next dial triggers a refresh too.
	go rotateLoop(ctx, guardianClient, getOAuthToken, tokens, pass)

	var listeners []net.Listener
	closeAll := func() {
		for _, l := range listeners {
			l.Close()
		}
	}

	if opts.socksAddr != "" {
		l, err := listenTCP(opts.socksAddr)
		if err != nil {
			return fmt.Errorf("SOCKS5: %w", err)
		}
		listeners = append(listeners, l)
		socks := &localproxy.Socks5Server{Dial: dialer.DialContext, Verbose: opts.verbose}
		go socks.Serve(l)
		log.Printf("SOCKS5 proxy listening on %s", opts.socksAddr)
	}
	if opts.httpAddr != "" {
		l, err := listenTCP(opts.httpAddr)
		if err != nil {
			closeAll()
			return fmt.Errorf("HTTP proxy: %w", err)
		}
		listeners = append(listeners, l)
		httpProxy := &localproxy.HTTPServer{Dial: dialer.DialContext, Verbose: opts.verbose}
		go httpProxy.Serve(l)
		log.Printf("HTTP CONNECT proxy listening on %s", opts.httpAddr)
	}
	if len(listeners) == 0 {
		return errors.New("all local listeners are disabled; nothing to do")
	}

	<-ctx.Done()
	log.Println("shutting down")
	closeAll()
	return nil
}

func rotateLoop(ctx context.Context, gc *guardian.Client, getOAuthToken func() (string, error), tokens *tunnel.AtomicToken, pass *guardian.ProxyPass) {
	for {
		rotateAt := pass.RotationTime()
		delay := time.Until(rotateAt)
		if delay < time.Second {
			delay = time.Second
		}
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}

		oauthToken, err := getOAuthToken()
		if err != nil {
			log.Printf("rotation: OAuth token refresh failed: %v (retrying in 30s)", err)
			if !sleepCtx(ctx, 30*time.Second) {
				return
			}
			continue
		}
		newPass, usage, err := gc.ProxyPass(oauthToken)
		if err != nil {
			var gerr *guardian.Error
			if errors.As(err, &gerr) && gerr.Kind == guardian.KindQuota {
				log.Printf("rotation: quota exceeded; pausing until %v", time.Now().Add(gerr.RetryAfter).Format(time.RFC3339))
				if !sleepCtx(ctx, maxDuration(gerr.RetryAfter, time.Minute)) {
					return
				}
				continue
			}
			log.Printf("rotation: pass refresh failed: %v (retrying in 30s)", err)
			if !sleepCtx(ctx, 30*time.Second) {
				return
			}
			continue
		}
		pass = newPass
		tokens.Set(pass.Token)
		printUsage(usage)
		log.Printf("rotation: new proxy pass valid until %s", time.Unix(pass.Exp, 0).Format(time.RFC3339))
	}
}

func sleepCtx(ctx context.Context, d time.Duration) bool {
	select {
	case <-ctx.Done():
		return false
	case <-time.After(d):
		return true
	}
}

// listenTCP wraps bind errors with actionable hints (port 1080 is commonly
// occupied by other proxy tools).
func listenTCP(addr string) (net.Listener, error) {
	l, err := net.Listen("tcp", addr)
	if err == nil {
		return l, nil
	}
	var opErr *net.OpError
	if errors.As(err, &opErr) && errors.Is(opErr.Err, syscall.EADDRINUSE) {
		return nil, fmt.Errorf("cannot listen on %s: %w (the port is already in use — pick another, e.g. --socks 127.0.0.1:2080)", addr, err)
	}
	return nil, fmt.Errorf("cannot listen on %s: %w", addr, err)
}

func maxDuration(a, b time.Duration) time.Duration {
	if a > b {
		return a
	}
	return b
}

// printCountries renders the exit-country table for --list-countries. Only
// non-quarantined servers count; a country showing 0 servers cannot be picked.
func printCountries(title string, countries []servers.Country) {
	count := func(n int, sing, plur string) string {
		if n == 1 {
			return fmt.Sprintf("%d %s", n, sing)
		}
		return fmt.Sprintf("%d %s", n, plur)
	}
	log.Printf("%s", title)
	for _, c := range countries {
		if c.Code == "REC" {
			continue
		}
		var nServers, nCities int
		for _, city := range c.Cities {
			usable := 0
			for _, s := range city.Servers {
				if !s.Quarantined {
					usable++
				}
			}
			if usable > 0 {
				nCities++
			}
			nServers += usable
		}
		locked := ""
		if c.Locked {
			locked = " (locked)"
		}
		log.Printf("  %-4s %-22s %s, %s%s",
			c.Code, c.Name, count(nServers, "server", "servers"), count(nCities, "city", "cities"), locked)
	}
}

func printUsage(u *guardian.Usage) {
	if u == nil {
		return
	}
	if u.Unlimited {
		log.Printf("Bandwidth: unlimited")
		return
	}
	reset := ""
	if !u.Reset.IsZero() {
		reset = " resets " + u.Reset.Format("2006-01-02")
	}
	limit, errLimit := parseBigInt(u.Limit)
	remaining, errRem := parseBigInt(u.Remaining)
	if errLimit != nil || errRem != nil || limit <= 0 {
		log.Printf("Bandwidth: remaining=%s limit=%s%s", u.Remaining, u.Limit, reset)
		return
	}
	used := limit - remaining
	if used < 0 {
		used = 0
	}
	log.Printf("Bandwidth: %s of %s used (%.0f%%), %s left%s",
		formatBytes(used), formatBytes(limit),
		100*float64(used)/float64(limit), formatBytes(remaining), reset)
}

func parseBigInt(s string) (int64, error) {
	var n int64
	if _, err := fmt.Sscanf(s, "%d", &n); err != nil {
		return 0, err
	}
	return n, nil
}

func formatBytes(n int64) string {
	const kib, mib, gib = 1024, 1024 * 1024, 1024 * 1024 * 1024
	switch {
	case n >= gib:
		return fmt.Sprintf("%.1f GiB", float64(n)/gib)
	case n >= mib:
		return fmt.Sprintf("%.1f MiB", float64(n)/mib)
	case n >= kib:
		return fmt.Sprintf("%.1f KiB", float64(n)/kib)
	default:
		return fmt.Sprintf("%d B", n)
	}
}

// resolveSession picks the session source: explicit token > interactive
// email/password login.
func resolveSession(opts *options) (*fxa.Session, error) {
	if opts.sessionToken != "" {
		if _, err := fxa.SessionAuthHeader(opts.sessionToken); err != nil {
			return nil, fmt.Errorf("bad --session-token: %w", err)
		}
		return &fxa.Session{Token: opts.sessionToken, Verified: true}, nil
	}
	if opts.email != "" {
		return interactiveLogin(opts)
	}
	return nil, errors.New("no credentials: pass --session-token (64 hex chars, see README) or --email/--password")
}

func interactiveLogin(opts *options) (*fxa.Session, error) {
	password := opts.password
	if password == "" {
		password = os.Getenv("FFVPN_PASSWORD")
	}
	if password == "" {
		fmt.Print("Firefox Account password: ")
		var line string
		fmt.Scanln(&line)
		password = line
	}
	client := fxa.NewClient(opts.authServer)
	session, err := client.Login(opts.email, password, opts.unblockCode)
	if err != nil {
		var apiErr *fxa.APIError
		if errors.As(err, &apiErr) && apiErr.Status == 406 {
			return nil, fmt.Errorf("Mozilla's edge protection rejects non-browser clients on /account/login (HTTP 406). " +
				"Sign in to your Firefox Account inside Firefox, then pass its sessionToken (from signedInUser.json, see README) via --session-token instead")
		}
		if fxa.IsErrno(err, fxa.ErrnoUnblockRequired) {
			return nil, fmt.Errorf("login blocked by FxA: request an unblock code via email and retry with --unblock-code")
		}
		return nil, err
	}
	if !session.Verified {
		exists, terr := client.TOTPExists(session)
		if terr == nil && exists {
			fmt.Print("Two-factor code (TOTP): ")
			var code string
			fmt.Scanln(&code)
			if err := client.VerifyTOTP(session, code); err != nil {
				return nil, err
			}
		} else {
			fmt.Println("Sign-in confirmation email sent; open it in your browser, then wait...")
			if err := client.WaitVerified(session, 5*time.Minute, 5*time.Second); err != nil {
				return nil, err
			}
		}
	}
	log.Printf("Logged in as %s", opts.email)
	return session, nil
}
