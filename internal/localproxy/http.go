package localproxy

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
)

// HTTPServer accepts HTTP CONNECT requests and relays them through Dial.
// Plain (non-CONNECT) requests are rejected: essentially all browser traffic
// is HTTPS, so CONNECT covers real use.
type HTTPServer struct {
	Dial    DialFunc
	Verbose bool
}

// Serve runs until the listener is closed.
func (s *HTTPServer) Serve(l net.Listener) error {
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

func (s *HTTPServer) logf(format string, args ...any) {
	if s.Verbose {
		fmt.Printf("[http] "+format+"\n", args...)
	}
}

func (s *HTTPServer) handle(conn net.Conn) {
	defer conn.Close()
	br := bufio.NewReader(conn)
	reqLine, err := br.ReadString('\n')
	if err != nil {
		return
	}
	parts := strings.Fields(strings.TrimRight(reqLine, "\r\n"))
	if len(parts) < 3 || !strings.EqualFold(parts[0], "CONNECT") {
		io.WriteString(conn, "HTTP/1.1 405 Method Not Allowed\r\nConnection: close\r\n\r\n")
		return
	}
	addr := parts[1]
	if _, _, err := net.SplitHostPort(addr); err != nil {
		io.WriteString(conn, "HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n")
		return
	}
	// Drain request headers.
	for {
		line, err := br.ReadString('\n')
		if err != nil || line == "\r\n" || line == "\n" {
			break
		}
	}

	s.logf("CONNECT %s", addr)
	upstream, err := s.Dial(context.Background(), "tcp", addr)
	if err != nil {
		s.logf("CONNECT %s failed: %v", addr, err)
		io.WriteString(conn, "HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n")
		return
	}
	defer upstream.Close()
	io.WriteString(conn, "HTTP/1.1 200 Connection established\r\n\r\n")

	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); io.Copy(upstream, br) }()
	go func() { defer wg.Done(); io.Copy(conn, upstream) }()
	wg.Wait()
}
