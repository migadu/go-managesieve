package managesieveserver_test

// Regression tests for two connection-wedge bugs:
//
//  1. The trailing-CRLF read after a literal body ran without a read
//     deadline (the deadline was cleared right after the body was
//     consumed), so a client that sent exactly the declared N octets and
//     then withheld the CRLF blocked the handler goroutine forever. The
//     same pattern existed pre-auth in the AUTHENTICATE initial-response
//     literal path.
//
//  2. Server.Close cancelled the context and waited on the connection
//     WaitGroup, but nothing unblocked a connection parked in a read:
//     shutdown stalled for up to IdleTimeout, or forever when IdleTimeout
//     was disabled.

import (
	"encoding/base64"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/migadu/go-managesieve/managesieveserver"
)

// startWedgeServer starts a server with a short idle timeout so a read that
// escapes its deadline is distinguishable (test client deadline 3s) from one
// that is properly bounded (server idle timeout 300ms).
func startWedgeServer(t *testing.T) string {
	t.Helper()
	return startServer(t, managesieveserver.Options{
		NewSession:    newTestStore().NewSession,
		InsecureAuth:  true,
		IdleTimeout:   300 * time.Millisecond,
		MaxScriptSize: 4096,
	})
}

// TestLiteralTrailingCRLFWithheld sends a PUTSCRIPT literal body of exactly
// the declared size and then withholds the terminating CRLF. The read that
// consumes that CRLF must be bounded by the idle timeout: the server has to
// answer NO and drop the connection instead of wedging the handler goroutine.
func TestLiteralTrailingCRLFWithheld(t *testing.T) {
	addr := startWedgeServer(t)
	c := dial(t, addr)
	c.authenticate("user@example.com", "secret")
	c.conn.SetDeadline(time.Now().Add(3 * time.Second))

	// Exactly 5 octets ("keep;"), no trailing CRLF, then silence.
	c.sendRaw("PUTSCRIPT \"x\" {5+}\r\nkeep;")

	resp, _ := c.readResponse()
	expectPrefix(t, resp, "NO")

	// The stream is desynced (the CRLF never arrived); the server must close.
	if line, err := c.r.ReadString('\n'); err == nil {
		t.Errorf("connection still open after withheld literal CRLF, got %q", line)
	}
}

// TestAuthenticateLiteralTrailingCRLFWithheld is the pre-auth variant: the
// AUTHENTICATE initial-response literal is followed by a withheld CRLF. An
// unauthenticated peer must not be able to park a connection forever.
func TestAuthenticateLiteralTrailingCRLFWithheld(t *testing.T) {
	addr := startWedgeServer(t)
	c := dial(t, addr)
	c.greet()
	c.conn.SetDeadline(time.Now().Add(3 * time.Second))

	payload := base64.StdEncoding.EncodeToString([]byte("\x00user@example.com\x00secret"))
	// Full literal body, no trailing CRLF, then silence.
	c.sendRaw(fmt.Sprintf("AUTHENTICATE \"PLAIN\" {%d+}\r\n%s", len(payload), payload))

	resp, _ := c.readResponse()
	expectPrefix(t, resp, "NO")

	if line, err := c.r.ReadString('\n'); err == nil {
		t.Errorf("connection still open after withheld auth literal CRLF, got %q", line)
	}
}

// closeServer runs srv.Close and fails the test if it does not return
// promptly.
func closeServer(t *testing.T, srv *managesieveserver.Server) {
	t.Helper()
	done := make(chan error, 1)
	go func() { done <- srv.Close() }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Server.Close did not return within 5s")
	}
}

// startOwnedServer starts a server whose Close the test drives itself (no
// t.Cleanup(Close), which would double-close).
func startOwnedServer(t *testing.T, opts managesieveserver.Options) (*managesieveserver.Server, string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := managesieveserver.New(opts)
	go srv.Serve(ln)
	return srv, ln.Addr().String()
}

// TestCloseUnblocksIdleConnection verifies that Server.Close does not wait
// for an idle connection's read deadline (default 30 minutes) to expire: the
// blocked read must be kicked immediately and the client told the server is
// going away.
func TestCloseUnblocksIdleConnection(t *testing.T) {
	srv, addr := startOwnedServer(t, managesieveserver.Options{
		NewSession:   newTestStore().NewSession,
		InsecureAuth: true,
		IdleTimeout:  10 * time.Minute,
	})

	c := dial(t, addr)
	c.greet() // greeting received => the connection is registered and idle

	closeServer(t, srv)

	resp, _ := c.readResponse()
	expectPrefix(t, resp, "BYE")
	if line, err := c.r.ReadString('\n'); err == nil {
		t.Errorf("connection still open after server close, got %q", line)
	}
}

// TestCloseUnblocksConnectionWithIdleTimeoutDisabled covers the worst case:
// IdleTimeout disabled (negative) and no AbsoluteSessionTimeout, so the idle
// read has no deadline at all. Without a force-unblock, Close never returns.
func TestCloseUnblocksConnectionWithIdleTimeoutDisabled(t *testing.T) {
	srv, addr := startOwnedServer(t, managesieveserver.Options{
		NewSession:   newTestStore().NewSession,
		InsecureAuth: true,
		IdleTimeout:  -1,
	})

	c := dial(t, addr)
	c.greet()

	closeServer(t, srv)

	resp, _ := c.readResponse()
	expectPrefix(t, resp, "BYE")
	if line, err := c.r.ReadString('\n'); err == nil {
		t.Errorf("connection still open after server close, got %q", line)
	}
}

// TestCloseLeavesHijackedConnUsable pins the ownership contract: a hijacked
// connection belongs to the hijacker, so Server.Close must neither close it
// nor poison its read deadline while kicking the connections it still owns.
func TestCloseLeavesHijackedConnUsable(t *testing.T) {
	var sess *hijackSession
	srv, addr := startOwnedServer(t, managesieveserver.Options{
		NewSession: func(conn *managesieveserver.Conn) (managesieveserver.Session, error) {
			sess = &hijackSession{conn: conn, hijacked: make(chan struct{})}
			return sess, nil
		},
		InsecureAuth: true,
		IdleTimeout:  10 * time.Minute,
	})

	c := dial(t, addr)
	c.greet()
	payload := base64.StdEncoding.EncodeToString([]byte("\x00user\x00secret"))
	c.send(fmt.Sprintf(`AUTHENTICATE "PLAIN" "%s"`, payload))
	if line := c.readLine(); line != `OK "Authenticated"` {
		t.Fatalf("hijack success line = %q", line)
	}

	// The hijacker's relay goroutine is now blocked reading the next line.
	closeServer(t, srv)

	// Reads on the hijacked conn must still work after Close: the relay
	// echoes the line back only if its blocked read survived the shutdown.
	c.send("PING")
	if line := c.readLine(); line != "RELAYED PING" {
		t.Fatalf("relay after Server.Close = %q, want %q", line, "RELAYED PING")
	}
	<-sess.hijacked
}
