package managesieveserver_test

// Regression tests for protocol-strictness findings: RFC 5804 command lines
// end with CRLF (bare LF and unterminated-at-EOF lines must not execute), the
// SASL capability is always advertised (empty when no mechanism is
// available), and PLAIN is advertised pre-TLS when InsecureAuth deliberately
// accepts it there.

import (
	"net"
	"strings"
	"testing"
	"time"

	"github.com/migadu/go-managesieve/managesieveserver"
)

func TestBareLFLineRejected(t *testing.T) {
	addr := startDefaultServer(t, newTestStore())
	c := dial(t, addr)
	c.greet()

	c.sendRaw("NOOP\n")
	resp, _ := c.readResponse()
	if resp != `NO "Command line must end with CRLF"` {
		t.Errorf("bare-LF line = %q", resp)
	}
	if line, err := c.r.ReadString('\n'); err == nil {
		t.Errorf("connection still open after bare-LF line, got %q", line)
	}
}

func TestUnterminatedLineAtEOFNotExecuted(t *testing.T) {
	addr := startDefaultServer(t, newTestStore())
	c := dial(t, addr)
	c.greet()

	// A command without a line terminator followed by FIN is not a
	// well-formed line and must not execute.
	c.sendRaw("NOOP")
	if err := c.conn.(*net.TCPConn).CloseWrite(); err != nil {
		t.Fatal(err)
	}
	resp, _ := c.readResponse()
	if resp != `NO "Command line must end with CRLF"` {
		t.Errorf("unterminated line at EOF = %q", resp)
	}
}

func TestSASLAdvertisedPreTLSWithInsecureAuth(t *testing.T) {
	store := newTestStore()
	addr := startServer(t, managesieveserver.Options{
		NewSession:   store.NewSession,
		TLSConfig:    serverTLSConfig(t),
		InsecureAuth: true,
		IdleTimeout:  5 * time.Second,
	})
	c := dial(t, addr)
	_, caps := c.greet()
	joined := strings.Join(caps, "\n")

	if !strings.Contains(joined, `"STARTTLS"`) {
		t.Errorf("STARTTLS not advertised:\n%s", joined)
	}
	// InsecureAuth means PLAIN is actually accepted pre-TLS, so hiding it
	// behind `"SASL" ""` misinforms the client.
	if !strings.Contains(joined, `"SASL" "PLAIN"`) {
		t.Errorf("PLAIN accepted pre-TLS (InsecureAuth) but not advertised:\n%s", joined)
	}
}
