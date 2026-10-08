package tunnel

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

func TestParseDialProxy(t *testing.T) {
	cases := []struct {
		raw     string
		address string
		user    string
		pass    string
		wantErr string
	}{
		{raw: "socks5://10.0.0.1:1080", address: "10.0.0.1:1080"},
		{raw: "socks5h://10.0.0.1:1080", address: "10.0.0.1:1080"},
		{raw: "SOCKS5://10.0.0.1:1080", address: "10.0.0.1:1080"},
		{raw: "socks5://10.0.0.1", address: "10.0.0.1:1080"},
		{raw: "socks5://alice:s3cr%40t@10.0.0.1:1080", address: "10.0.0.1:1080", user: "alice", pass: "s3cr@t"},
		{raw: "socks5://alice@10.0.0.1:9050", address: "10.0.0.1:9050", user: "alice"},
		{raw: "socks5://", wantErr: "missing host"},
		{raw: "http://10.0.0.1:8080", wantErr: "unsupported"},
		{raw: "10.0.0.1:1080", wantErr: "unsupported"},
	}
	for _, c := range cases {
		got, err := ParseDialProxy(c.raw)
		if c.wantErr != "" {
			if err == nil || !strings.Contains(err.Error(), c.wantErr) {
				t.Errorf("ParseDialProxy(%q) error = %v, want substring %q", c.raw, err, c.wantErr)
			}
			continue
		}
		if err != nil {
			t.Errorf("ParseDialProxy(%q) unexpected error: %v", c.raw, err)
			continue
		}
		if got.Address != c.address || got.User != c.user || got.Pass != c.pass {
			t.Errorf("ParseDialProxy(%q) = %+v, want address=%q user=%q pass=%q",
				c.raw, got, c.address, c.user, c.pass)
		}
	}
}

func TestDescribeDialProxyMasksPassword(t *testing.T) {
	got := DescribeDialProxy("socks5://alice:hunter2@10.0.0.1:1080")
	if strings.Contains(got, "hunter2") {
		t.Errorf("DescribeDialProxy leaked the password: %q", got)
	}
	if got != "socks5://alice:****@10.0.0.1:1080" {
		t.Errorf("DescribeDialProxy = %q", got)
	}
	if plain := DescribeDialProxy("socks5h://10.0.0.1:1080"); plain != "socks5h://10.0.0.1:1080" {
		t.Errorf("DescribeDialProxy = %q", plain)
	}
}

// fakeSocks5 serves SOCKS5 sessions that demand username/password auth and
// accept a CONNECT only with the expected credentials.
func fakeSocks5(t *testing.T, user, pass string) (addr string, done func()) {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	served := make(chan struct{})
	go func() {
		defer close(served)
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			go serveSocks5Session(conn, user, pass)
		}
	}()
	return l.Addr().String(), func() {
		l.Close()
		<-served
	}
}

func serveSocks5Session(conn net.Conn, user, pass string) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

	greeting := make([]byte, 2)
	if _, err := io.ReadFull(conn, greeting); err != nil {
		return
	}
	methods := make([]byte, int(greeting[1]))
	if _, err := io.ReadFull(conn, methods); err != nil {
		return
	}
	if _, err := conn.Write([]byte{0x05, 0x02}); err != nil { // demand auth
		return
	}

	authHdr := make([]byte, 2)
	if _, err := io.ReadFull(conn, authHdr); err != nil {
		return
	}
	u := make([]byte, int(authHdr[1]))
	if _, err := io.ReadFull(conn, u); err != nil {
		return
	}
	pl := make([]byte, 1)
	if _, err := io.ReadFull(conn, pl); err != nil {
		return
	}
	p := make([]byte, int(pl[0]))
	if _, err := io.ReadFull(conn, p); err != nil {
		return
	}
	status := byte(0x01)
	if string(u) == user && string(p) == pass {
		status = 0x00
	}
	if _, err := conn.Write([]byte{0x01, status}); err != nil {
		return
	}
	if status != 0x00 {
		return
	}

	reqHdr := make([]byte, 4)
	if _, err := io.ReadFull(conn, reqHdr); err != nil {
		return
	}
	if reqHdr[3] == 0x03 {
		lenBuf := make([]byte, 1)
		if _, err := io.ReadFull(conn, lenBuf); err != nil {
			return
		}
		if _, err := io.ReadFull(conn, make([]byte, int(lenBuf[0]))); err != nil {
			return
		}
	}
	port := make([]byte, 2)
	if _, err := io.ReadFull(conn, port); err != nil {
		return
	}
	reply := []byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0}
	reply = append(reply, port...)
	_, _ = conn.Write(reply)
}

func TestSocksDialAuth(t *testing.T) {
	proxy, done := fakeSocks5(t, "alice", "hunter2")
	defer done()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	conn, err := socksDialAuth(ctx, "tcp", proxy, "example.test:443", "alice", "hunter2")
	if err != nil {
		t.Fatalf("socksDialAuth: %v", err)
	}
	conn.Close()

	if _, err := socksDialAuth(ctx, "tcp", proxy, "example.test:443", "alice", "wrong"); err == nil {
		t.Fatal("socksDialAuth accepted bad credentials")
	}
}

func TestSocksDialAuthRejectsUnknownAuthMethod(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer l.Close()
	go func() {
		conn, err := l.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
		greeting := make([]byte, 2)
		if _, err := io.ReadFull(conn, greeting); err != nil {
			return
		}
		methods := make([]byte, int(greeting[1]))
		if _, err := io.ReadFull(conn, methods); err != nil {
			return
		}
		_, _ = conn.Write([]byte{0x05, 0xFF}) // no acceptable method
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := socksDialAuth(ctx, "tcp", l.Addr().String(), "example.test:443", "", ""); err == nil {
		t.Fatal("socksDialAuth accepted an unusable auth method")
	}
}

func TestReadFullIgnoresPartialReads(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	go func() {
		buf := make([]byte, 4)
		binary.BigEndian.PutUint32(buf, 0xDEADBEEF)
		for _, b := range buf {
			_, _ = server.Write([]byte{b})
		}
	}()

	got := make([]byte, 4)
	n, err := readFull(client, got)
	if err != nil || n != 4 {
		t.Fatalf("readFull = (%d, %v), want (4, nil)", n, err)
	}
	if binary.BigEndian.Uint32(got) != 0xDEADBEEF {
		t.Fatalf("readFull returned %x", got)
	}
}
