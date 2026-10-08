package localproxy_test

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
	"encoding/binary"
	"fmt"
	"io"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"

	"ffvpn/internal/localproxy"
	"ffvpn/internal/tunnel"
)

// selfCert mints a throwaway TLS certificate for the fake edge.
func selfCert(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "edge.test"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"edge.test"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// fakeEdge is a TLS server that requires a CONNECT request carrying the
// expected bearer token, then echoes all bytes back (acting as the tunnel
// exit for the test).
func fakeEdge(t *testing.T, wantAuth string) string {
	t.Helper()
	cert := selfCert(t)
	inner, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	l := tls.NewListener(inner, &tls.Config{Certificates: []tls.Certificate{cert}})
	t.Cleanup(func() { l.Close() })

	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				br := bufio.NewReader(conn)
				reqLine, err := br.ReadString('\n')
				if err != nil {
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
				if auth != wantAuth {
					conn.Write([]byte("HTTP/1.1 403 Forbidden\r\n\r\n"))
					return
				}
				if !strings.HasPrefix(reqLine, "CONNECT ") {
					conn.Write([]byte("HTTP/1.1 405 Method Not Allowed\r\n\r\n"))
					return
				}
				conn.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n"))
				io.Copy(conn, br)
			}()
		}
	}()
	return l.Addr().String()
}

// socks5DialClient is a minimal SOCKS5 client for exercising the local server.
func socks5DialClient(t *testing.T, proxyAddr, target string) net.Conn {
	t.Helper()
	conn, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		t.Fatal(err)
	}
	greet := make([]byte, 2)
	if _, err := io.ReadFull(conn, greet); err != nil {
		t.Fatal(err)
	}
	if greet[0] != 0x05 || greet[1] != 0x00 {
		t.Fatalf("proxy chose method %d", greet[1])
	}
	host, portStr, _ := net.SplitHostPort(target)
	var port uint16
	fmt.Sscanf(portStr, "%d", &port)
	req := []byte{0x05, 0x01, 0x00, 0x03, byte(len(host))}
	req = append(req, host...)
	var portBytes [2]byte
	binary.BigEndian.PutUint16(portBytes[:], port)
	req = append(req, portBytes[:]...)
	if _, err := conn.Write(req); err != nil {
		t.Fatal(err)
	}
	reply := make([]byte, 10)
	if _, err := io.ReadFull(conn, reply); err != nil {
		t.Fatal(err)
	}
	if reply[1] != 0x00 {
		t.Fatalf("socks5 CONNECT refused: code %d", reply[1])
	}
	return conn
}

func TestSocks5ThroughTunnel(t *testing.T) {
	const wantJWT = "test-jwt-abc123"
	edge := fakeEdge(t, "Bearer "+wantJWT)

	dialer := &tunnel.Dialer{
		HostPort:           edge,
		ServerName:         "edge.test",
		Token:              tunnel.StaticToken(wantJWT),
		InsecureSkipVerify: true,
	}
	socksLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer socksLn.Close()
	socks := &localproxy.Socks5Server{Dial: dialer.DialContext}
	go socks.Serve(socksLn)

	conn := socks5DialClient(t, socksLn.Addr().String(), "example.org:443")
	defer conn.Close()

	payload := []byte("hello through the firefox vpn edge")
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Write(payload); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("echo mismatch: got %q", got)
	}
}

func TestHTTPConnectThroughTunnel(t *testing.T) {
	const wantJWT = "http-jwt-42"
	edge := fakeEdge(t, "Bearer "+wantJWT)

	dialer := &tunnel.Dialer{
		HostPort:           edge,
		ServerName:         "edge.test",
		Token:              tunnel.StaticToken(wantJWT),
		InsecureSkipVerify: true,
	}
	httpLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer httpLn.Close()
	httpProxy := &localproxy.HTTPServer{Dial: dialer.DialContext}
	go httpProxy.Serve(httpLn)

	conn, err := net.Dial("tcp", httpLn.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	fmt.Fprintf(conn, "CONNECT example.org:443 HTTP/1.1\r\nHost: example.org:443\r\n\r\n")

	br := bufio.NewReader(conn)
	status, err := br.ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(status, "200") {
		t.Fatalf("expected 200, got %q", status)
	}
	for {
		line, err := br.ReadString('\n')
		if err != nil || line == "\r\n" {
			break
		}
	}

	payload := []byte("over http connect")
	if _, err := conn.Write(payload); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("echo mismatch: got %q", got)
	}
}

// The Dialer must surface auth failures distinctly so the rotation loop can
// react to a rejected token.
func TestTunnelRejectsBadToken(t *testing.T) {
	edge := fakeEdge(t, "Bearer good-token")
	dialer := &tunnel.Dialer{
		HostPort:           edge,
		ServerName:         "edge.test",
		Token:              tunnel.StaticToken("bad-token"),
		InsecureSkipVerify: true,
	}
	_, err := dialer.DialContext(context.Background(), "tcp", "example.org:443")
	if err != tunnel.ErrTokenRejected {
		t.Fatalf("want ErrTokenRejected, got %v", err)
	}
}
