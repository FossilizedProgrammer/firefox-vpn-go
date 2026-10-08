// Package localproxy exposes local SOCKS5 and HTTP CONNECT proxies that
// forward every connection through the IP Protection tunnel.
package localproxy

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
)

// DialFunc dials a target "host:port", typically tunnel.Dialer.DialContext.
type DialFunc func(ctx context.Context, network, addr string) (net.Conn, error)

// Socks5Server accepts SOCKS5 CONNECT commands (RFC 1928). Optional
// username/password auth can be enforced.
type Socks5Server struct {
	Dial    DialFunc
	User    string // optional; both must be set to require auth
	Pass    string
	Verbose bool
}

// Serve runs until the listener is closed.
func (s *Socks5Server) Serve(l net.Listener) error {
	for {
		conn, err := l.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		go s.handle(conn)
	}
}

func (s *Socks5Server) logf(format string, args ...any) {
	if s.Verbose {
		fmt.Printf("[socks5] "+format+"\n", args...)
	}
}

func (s *Socks5Server) handle(conn net.Conn) {
	defer conn.Close()
	br := bufio.NewReader(conn)

	// Method negotiation.
	head := make([]byte, 2)
	if _, err := io.ReadFull(br, head); err != nil {
		return
	}
	if head[0] != 0x05 {
		return
	}
	n := int(head[1])
	methods := make([]byte, n)
	if _, err := io.ReadFull(br, methods); err != nil {
		return
	}
	wantAuth := s.User != "" && s.Pass != ""
	var chosen byte = 0xFF
	for _, m := range methods {
		if wantAuth && m == 0x02 {
			chosen = 0x02
			break
		}
		if !wantAuth && m == 0x00 {
			chosen = 0x00
			break
		}
	}
	if chosen == 0xFF {
		conn.Write([]byte{0x05, 0xFF})
		return
	}
	conn.Write([]byte{0x05, chosen})

	if chosen == 0x02 {
		ver := make([]byte, 2) // version + username length
		if _, err := io.ReadFull(br, ver); err != nil || ver[0] != 0x01 {
			return
		}
		user := make([]byte, ver[1])
		if _, err := io.ReadFull(br, user); err != nil {
			return
		}
		plen := make([]byte, 1)
		if _, err := io.ReadFull(br, plen); err != nil {
			return
		}
		pass := make([]byte, plen[0])
		if _, err := io.ReadFull(br, pass); err != nil {
			return
		}
		if string(user) != s.User || string(pass) != s.Pass {
			conn.Write([]byte{0x01, 0x01})
			return
		}
		conn.Write([]byte{0x01, 0x00})
	}

	// Request: VER CMD RSV ATYP DST.ADDR DST.PORT.
	req := make([]byte, 4)
	if _, err := io.ReadFull(br, req); err != nil {
		return
	}
	if req[1] != 0x01 { // CONNECT only
		s.reply(conn, req[0], 0x07)
		return
	}
	var host string
	switch req[3] {
	case 0x01:
		ip := make([]byte, 4)
		if _, err := io.ReadFull(br, ip); err != nil {
			return
		}
		host = net.IP(ip).String()
	case 0x03:
		lenBuf := make([]byte, 1)
		if _, err := io.ReadFull(br, lenBuf); err != nil {
			return
		}
		name := make([]byte, lenBuf[0])
		if _, err := io.ReadFull(br, name); err != nil {
			return
		}
		host = string(name)
	case 0x04:
		ip := make([]byte, 16)
		if _, err := io.ReadFull(br, ip); err != nil {
			return
		}
		host = net.IP(ip).String()
	default:
		s.reply(conn, req[0], 0x08)
		return
	}
	portBuf := make([]byte, 2)
	if _, err := io.ReadFull(br, portBuf); err != nil {
		return
	}
	port := binary.BigEndian.Uint16(portBuf)
	addr := net.JoinHostPort(host, fmt.Sprintf("%d", port))

	s.logf("CONNECT %s", addr)
	upstream, err := s.Dial(context.Background(), "tcp", addr)
	if err != nil {
		s.logf("CONNECT %s failed: %v", addr, err)
		s.reply(conn, req[0], 0x05) // connection refused
		return
	}
	defer upstream.Close()
	s.reply(conn, req[0], 0x00)

	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); io.Copy(upstream, br) }()
	go func() { defer wg.Done(); io.Copy(conn, upstream) }()
	wg.Wait()
}

func (s *Socks5Server) reply(conn net.Conn, ver, code byte) {
	// BND.ADDR 0.0.0.0, BND.PORT 0.
	conn.Write([]byte{ver, code, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
}
