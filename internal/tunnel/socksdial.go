package tunnel

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
)

// DialProxy is a parsed socks5:// bootstrap proxy URL.
type DialProxy struct {
	// Network is always "tcp" — kept for symmetry with net.Dialer calls.
	Network string
	// Address is the proxy as "host:port".
	Address string
	// User/Pass are optional RFC 1929 credentials (empty = no auth).
	User string
	Pass string
}

// ParseDialProxy validates a socks5://[user:pass@]host:port bootstrap proxy
// URL (socks5h:// is accepted as a synonym; the client always asks the proxy
// to resolve the target hostname).
func ParseDialProxy(raw string) (DialProxy, error) {
	schemeEnd := strings.Index(raw, "://")
	if schemeEnd < 0 {
		return DialProxy{}, fmt.Errorf("tunnel: unsupported dial proxy %q (only socks5:// and socks5h:// are supported)", raw)
	}
	// url.Parse lowercases nothing for us; normalise the scheme first so a
	// SOCKS5:// spelling still matches.
	normalized := strings.ToLower(raw[:schemeEnd]) + raw[schemeEnd:]
	u, err := url.Parse(normalized)
	if err != nil {
		return DialProxy{}, fmt.Errorf("tunnel: bad dial proxy %q: %w", raw, err)
	}
	if u.Scheme != "socks5" && u.Scheme != "socks5h" {
		return DialProxy{}, fmt.Errorf("tunnel: unsupported dial proxy %q (only socks5:// and socks5h:// are supported)", raw)
	}
	host, port := u.Hostname(), u.Port()
	if host == "" {
		return DialProxy{}, errors.New("tunnel: dial proxy URL missing host")
	}
	if port == "" {
		port = "1080"
	}
	proxy := DialProxy{
		Network: "tcp",
		Address: net.JoinHostPort(host, port),
	}
	if u.User != nil {
		proxy.User = u.User.Username()
		proxy.Pass, _ = u.User.Password()
	}
	return proxy, nil
}

// DescribeDialProxy renders a proxy URL for logs with the password masked.
func DescribeDialProxy(raw string) string {
	proxy, err := ParseDialProxy(raw)
	if err != nil {
		return raw
	}
	scheme := "socks5"
	if strings.HasPrefix(strings.ToLower(raw), "socks5h://") {
		scheme = "socks5h"
	}
	if proxy.User == "" {
		return scheme + "://" + proxy.Address
	}
	masked := proxy.User + ":****@"
	return scheme + "://" + masked + proxy.Address
}

// socksDialAuth connects to target via a SOCKS5 proxy (RFC 1928), offering
// RFC 1929 username/password authentication when credentials are given.
// Minimal client used for the --dial-proxy option.
func socksDialAuth(ctx context.Context, network, proxyAddr, target, user, pass string) (net.Conn, error) {
	var nd net.Dialer
	conn, err := nd.DialContext(ctx, network, proxyAddr)
	if err != nil {
		return nil, fmt.Errorf("tunnel: dialing bootstrap proxy %s failed: %w", proxyAddr, err)
	}
	fail := func(err error) (net.Conn, error) {
		conn.Close()
		return nil, err
	}

	host, portStr, err := net.SplitHostPort(target)
	if err != nil {
		return fail(fmt.Errorf("tunnel: bad target %q: %w", target, err))
	}
	port, err := parsePort(portStr)
	if err != nil {
		return fail(err)
	}

	// Greeting: offer no-auth, plus username/password when we have any.
	greeting := []byte{0x05, 0x01, 0x00}
	if user != "" || pass != "" {
		greeting = []byte{0x05, 0x02, 0x00, 0x02}
	}
	if _, err := conn.Write(greeting); err != nil {
		return fail(err)
	}
	chosen := make([]byte, 2)
	if _, err := readFull(conn, chosen); err != nil {
		return fail(fmt.Errorf("tunnel: proxy greeting failed: %w", err))
	}
	if chosen[0] != 0x05 {
		return fail(fmt.Errorf("tunnel: unexpected proxy version %d", chosen[0]))
	}
	switch chosen[1] {
	case 0x00:
		// No authentication required (or accepted).
	case 0x02:
		if err := socksAuth(conn, user, pass); err != nil {
			return fail(err)
		}
	default:
		return fail(fmt.Errorf("tunnel: proxy offered no usable auth method (ver=%d method=%d)", chosen[0], chosen[1]))
	}

	// CONNECT request; send the hostname and let the proxy resolve it.
	req := []byte{0x05, 0x01, 0x00, 0x03, byte(len(host))}
	req = append(req, host...)
	req = append(req, byte(port>>8), byte(port))
	if _, err := conn.Write(req); err != nil {
		return fail(err)
	}
	reply := make([]byte, 4)
	if _, err := readFull(conn, reply); err != nil {
		return fail(fmt.Errorf("tunnel: proxy connect failed: %w", err))
	}
	if reply[1] != 0x00 {
		return fail(fmt.Errorf("tunnel: proxy CONNECT refused (code %d)", reply[1]))
	}
	// Skip BND.ADDR/BND.PORT.
	switch reply[3] {
	case 0x01:
		if _, err := readFull(conn, make([]byte, 6)); err != nil {
			return fail(err)
		}
	case 0x03:
		lenBuf := make([]byte, 1)
		if _, err := readFull(conn, lenBuf); err != nil {
			return fail(err)
		}
		if _, err := readFull(conn, make([]byte, int(lenBuf[0])+2)); err != nil {
			return fail(err)
		}
	case 0x04:
		if _, err := readFull(conn, make([]byte, 18)); err != nil {
			return fail(err)
		}
	default:
		return fail(fmt.Errorf("tunnel: proxy sent unknown address type %d", reply[3]))
	}
	return conn, nil
}

// socksAuth performs the RFC 1929 username/password sub-negotiation.
func socksAuth(conn net.Conn, user, pass string) error {
	if len(user) > 255 || len(pass) > 255 {
		return errors.New("tunnel: proxy credentials longer than 255 bytes")
	}
	req := []byte{0x01, byte(len(user))}
	req = append(req, user...)
	req = append(req, byte(len(pass)))
	req = append(req, pass...)
	if _, err := conn.Write(req); err != nil {
		return fmt.Errorf("tunnel: proxy auth failed: %w", err)
	}
	reply := make([]byte, 2)
	if _, err := readFull(conn, reply); err != nil {
		return fmt.Errorf("tunnel: proxy auth failed: %w", err)
	}
	if reply[1] != 0x00 {
		return fmt.Errorf("tunnel: proxy rejected the credentials (status %d)", reply[1])
	}
	return nil
}

func parsePort(s string) (uint16, error) {
	var p int
	_, err := fmt.Sscanf(s, "%d", &p)
	if err != nil || p <= 0 || p > 65535 {
		return 0, fmt.Errorf("tunnel: bad port %q", s)
	}
	return uint16(p), nil
}

func readFull(conn net.Conn, buf []byte) (int, error) {
	total := 0
	for total < len(buf) {
		n, err := conn.Read(buf[total:])
		total += n
		if err != nil {
			return total, err
		}
	}
	return total, nil
}
