// Package tunnel dials the IP Protection proxy edge: a TLS connection to the
// Fastly MASQUE/CONNECT host followed by an HTTP CONNECT request carrying the
// ProxyPass JWT as a Proxy-Authorization Bearer header.
package tunnel

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Sentinel errors the caller can act on.
var (
	ErrTokenRejected = errors.New("tunnel: proxy rejected the token")
	ErrQuota         = errors.New("tunnel: quota exceeded at proxy")
	ErrUnavailable   = errors.New("tunnel: proxy unavailable")
)

// TokenSource returns the current ProxyPass JWT (thread-safe).
type TokenSource interface {
	BearerToken() string
}

type staticToken string

func (s staticToken) BearerToken() string { return string(s) }

// StaticToken wraps a fixed JWT for tests and simple uses.
func StaticToken(jwt string) TokenSource { return staticToken(jwt) }

// Dialer creates proxied connections through the edge.
type Dialer struct {
	// HostPort of the proxy edge, e.g. "faor73.m1.fastly-masque.net:2499".
	HostPort string
	// TLS ServerName (SNI) defaults to the host part of HostPort; a custom
	// value is only put in the ClientHello — the certificate is still
	// verified against the edge hostname.
	ServerName string
	// Token must yield a fresh-enough JWT; dialed connections use whatever
	// is current at dial time.
	Token TokenSource
	// DialThrough optionally dials the edge via another proxy
	// (socks5://[user:pass@]host:port) — useful when the edge is not
	// directly reachable.
	DialThrough string
	// InsecureSkipVerify disables TLS verification of the edge certificate.
	// For tests and self-signed lab setups; never enable in production.
	InsecureSkipVerify bool
	// Timeout covers dial+TLS+CONNECT.
	Timeout time.Duration
}

func (d *Dialer) tlsConfig() *tls.Config {
	host := d.HostPort
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	name := d.ServerName
	if name == "" {
		name = host
	}
	cfg := &tls.Config{ServerName: name, InsecureSkipVerify: d.InsecureSkipVerify}
	if name != host && !d.InsecureSkipVerify {
		// A caller-supplied SNI is only meant for the ClientHello: the
		// certificate presented by the edge still belongs to the edge
		// hostname, so verify the chain against that name while sending
		// `name` as SNI. Without this the handshake would always fail.
		expected := host
		cfg.InsecureSkipVerify = true
		cfg.VerifyPeerCertificate = func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			return verifyChainFor(rawCerts, expected)
		}
	}
	return cfg
}

// verifyChainFor validates a raw peer chain against the system roots and the
// given DNS name (verification of raw certs skips the usual tls.Config path,
// so the chain of trust has to be checked explicitly).
func verifyChainFor(rawCerts [][]byte, dnsName string) error {
	if len(rawCerts) == 0 {
		return errors.New("tunnel: proxy edge sent no certificate")
	}
	leaf, err := x509.ParseCertificate(rawCerts[0])
	if err != nil {
		return fmt.Errorf("tunnel: parsing edge certificate: %w", err)
	}
	intermediates := x509.NewCertPool()
	for _, raw := range rawCerts[1:] {
		if cert, err := x509.ParseCertificate(raw); err == nil {
			intermediates.AddCert(cert)
		}
	}
	if _, err := leaf.Verify(x509.VerifyOptions{
		DNSName:       dnsName,
		Intermediates: intermediates,
	}); err != nil {
		return fmt.Errorf("tunnel: edge certificate is not valid for %s: %w", dnsName, err)
	}
	return nil
}

// DialContext connects to the edge and issues CONNECT for addr ("host:port").
// The proxy resolves the hostname, mirroring Firefox's
// TRANSPARENT_PROXY_RESOLVES_HOST behavior.
func (d *Dialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	if network != "tcp" {
		return nil, fmt.Errorf("tunnel: unsupported network %q", network)
	}
	if _, _, err := net.SplitHostPort(addr); err != nil {
		return nil, fmt.Errorf("tunnel: target must be host:port: %w", err)
	}
	timeout := d.Timeout
	if timeout == 0 {
		timeout = 30 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	raw, err := d.dialRaw(ctx)
	if err != nil {
		return nil, err
	}
	tlsConn := tls.Client(raw, d.tlsConfig())
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		raw.Close()
		return nil, fmt.Errorf("tunnel: TLS handshake with %s failed: %w", d.HostPort, err)
	}
	if err := d.connect(ctx, tlsConn, addr); err != nil {
		tlsConn.Close()
		return nil, err
	}
	return tlsConn, nil
}

func (d *Dialer) dialRaw(ctx context.Context) (net.Conn, error) {
	if d.DialThrough == "" {
		var nd net.Dialer
		return nd.DialContext(ctx, "tcp", d.HostPort)
	}
	proxy, err := ParseDialProxy(d.DialThrough)
	if err != nil {
		return nil, err
	}
	return socksDialAuth(ctx, proxy.Network, proxy.Address, d.HostPort, proxy.User, proxy.Pass)
}

func (d *Dialer) connect(ctx context.Context, conn net.Conn, addr string) error {
	token := d.Token.BearerToken()
	req := strings.Join([]string{
		"CONNECT " + addr + " HTTP/1.1",
		"Host: " + addr,
		"Proxy-Authorization: Bearer " + token,
		"User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:157.0) Gecko/20100101 Firefox/157.0",
		"", "",
	}, "\r\n")
	if deadline, ok := ctx.Deadline(); ok {
		conn.SetDeadline(deadline)
		defer conn.SetDeadline(time.Time{})
	}
	if _, err := conn.Write([]byte(req)); err != nil {
		return fmt.Errorf("tunnel: sending CONNECT failed: %w", err)
	}
	br := bufio.NewReader(conn)
	status, err := br.ReadString('\n')
	if err != nil {
		return fmt.Errorf("tunnel: reading CONNECT response failed: %w", err)
	}
	// Drain headers so the connection is aligned for relaying.
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			return fmt.Errorf("tunnel: reading CONNECT response failed: %w", err)
		}
		if line == "\r\n" || line == "\n" {
			break
		}
	}
	code, err := parseStatusCode(status)
	if err != nil {
		return err
	}
	switch {
	case code == 200:
		return nil
	case code == 401 || code == 403 || code == 407:
		return ErrTokenRejected
	case code == 429:
		return ErrQuota
	default:
		return fmt.Errorf("%w: CONNECT status %d", ErrUnavailable, code)
	}
}

func parseStatusCode(statusLine string) (int, error) {
	parts := strings.Fields(strings.TrimRight(statusLine, "\r\n"))
	if len(parts) < 2 || !strings.HasPrefix(parts[0], "HTTP/") {
		return 0, fmt.Errorf("tunnel: malformed CONNECT response: %q", statusLine)
	}
	code, err := strconv.Atoi(parts[1])
	if err != nil {
		return 0, fmt.Errorf("tunnel: malformed status code in %q", statusLine)
	}
	return code, nil
}

// AtomicToken is a mutex-guarded ProxyPass holder implementing TokenSource.
type AtomicToken struct {
	mu   sync.RWMutex
	pass *guardianPass
}

// guardianPass avoids importing the guardian package here; only the JWT
// string is needed on the wire.
type guardianPass struct{ jwt string }

func NewAtomicToken(jwt string) *AtomicToken {
	return &AtomicToken{pass: &guardianPass{jwt: jwt}}
}

func (a *AtomicToken) Set(jwt string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.pass = &guardianPass{jwt: jwt}
}

func (a *AtomicToken) BearerToken() string {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.pass.jwt
}
