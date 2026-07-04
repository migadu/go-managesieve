package managesieveserver_test

import (
	"bufio"
	"context"
	"encoding/base64"
	"fmt"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/migadu/go-managesieve/managesieve"
	"github.com/migadu/go-managesieve/managesieveserver"
)

// hijackSession hijacks the connection during AuthenticatePlain, emulating a
// proxy taking over the relay after authenticating the user.
type hijackSession struct {
	conn       *managesieveserver.Conn
	closed     atomic.Int32
	hijacked   chan struct{}
	relayBytes string
}

func (s *hijackSession) Close() error {
	s.closed.Add(1)
	return nil
}

func (s *hijackSession) AuthenticatePlain(ctx context.Context, identity, username, password string) error {
	if password != "secret" {
		return &managesieveserver.Error{Message: "Authentication failed"}
	}
	netConn, reader, err := s.conn.Hijack()
	if err != nil {
		return &managesieveserver.Error{Code: "TRYLATER", Message: "Service temporarily unavailable", Close: true}
	}
	go func() {
		defer close(s.hijacked)
		defer netConn.Close()
		// Success line, as a proxy would write after backend auth.
		fmt.Fprintf(netConn, "OK \"Authenticated\"\r\n")
		// Prove pipelined bytes survive the hand-off: relay the next command
		// line back verbatim.
		line, err := reader.ReadString('\n')
		if err != nil {
			return
		}
		s.relayBytes = line
		fmt.Fprintf(netConn, "RELAYED %s", line)
	}()
	return nil
}

func (s *hijackSession) ListScripts(context.Context) ([]managesieve.ScriptInfo, error) {
	return nil, fmt.Errorf("not implemented")
}
func (s *hijackSession) GetScript(context.Context, string) (string, error) {
	return "", fmt.Errorf("not implemented")
}
func (s *hijackSession) PutScript(context.Context, string, string) (bool, error) {
	return false, fmt.Errorf("not implemented")
}
func (s *hijackSession) CheckScript(context.Context, string) (string, error) {
	return "", fmt.Errorf("not implemented")
}
func (s *hijackSession) SetActive(context.Context, string) error {
	return fmt.Errorf("not implemented")
}
func (s *hijackSession) DeleteScript(context.Context, string) error {
	return fmt.Errorf("not implemented")
}
func (s *hijackSession) RenameScript(context.Context, string, string) error {
	return fmt.Errorf("not implemented")
}
func (s *hijackSession) HaveSpace(context.Context, string, int64) error {
	return fmt.Errorf("not implemented")
}

func TestHijack(t *testing.T) {
	var sess *hijackSession
	addr := startServer(t, managesieveserver.Options{
		NewSession: func(conn *managesieveserver.Conn) (managesieveserver.Session, error) {
			sess = &hijackSession{conn: conn, hijacked: make(chan struct{})}
			return sess, nil
		},
		InsecureAuth: true,
		IdleTimeout:  5 * time.Second,
	})

	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(10 * time.Second))
	r := bufio.NewReader(conn)

	// Greeting.
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			t.Fatal(err)
		}
		if line[0] == 'O' { // OK line ends the greeting
			break
		}
	}

	// Authenticate with a pipelined follow-up command in the same segment:
	// the hijacker must see it via the handed-off reader.
	payload := base64.StdEncoding.EncodeToString([]byte("\x00user\x00secret"))
	fmt.Fprintf(conn, "AUTHENTICATE \"PLAIN\" \"%s\"\r\nLISTSCRIPTS\r\n", payload)

	line, err := r.ReadString('\n')
	if err != nil || line != "OK \"Authenticated\"\r\n" {
		t.Fatalf("hijack success line = %q, %v", line, err)
	}
	line, err = r.ReadString('\n')
	if err != nil || line != "RELAYED LISTSCRIPTS\r\n" {
		t.Fatalf("pipelined relay = %q, %v", line, err)
	}

	<-sess.hijacked

	// The library must not write anything further nor close prematurely; the
	// hijacker closed the conn, so the next read is EOF.
	if extra, err := r.ReadString('\n'); err == nil {
		t.Errorf("unexpected extra bytes after hijack: %q", extra)
	}

	// Session.Close still runs exactly once during teardown.
	deadline := time.Now().Add(2 * time.Second)
	for sess.closed.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if got := sess.closed.Load(); got != 1 {
		t.Errorf("Session.Close called %d times, want 1", got)
	}
}
