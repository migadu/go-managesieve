package managesieveserver_test

import (
	"context"
	"encoding/base64"
	"sync"
	"testing"
	"time"

	"github.com/migadu/go-managesieve/managesieveserver"
)

// recordingAuthSession records the PLAIN fields the library hands it and
// refuses every login with a reply of its own, so a test sees whose verdict
// reached the client.
type recordingAuthSession struct {
	managesieveserver.Session
	mu    sync.Mutex
	calls [][3]string
}

func (s *recordingAuthSession) AuthenticatePlain(_ context.Context, identity, username, password string) error {
	s.mu.Lock()
	s.calls = append(s.calls, [3]string{identity, username, password})
	s.mu.Unlock()
	return &managesieveserver.Error{Message: `"Refused by the session"`}
}

// TestAuthenticatePlainPassesAnEmptyPasswordToTheSession: the library hands the
// decoded PLAIN fields to the session unchanged, an empty password included, so
// the server decides about it like any other failed login (rate limiting,
// failure counters). The attempt still costs one MaxErrors error, like any
// refused AUTHENTICATE. (#9)
func TestAuthenticatePlainPassesAnEmptyPasswordToTheSession(t *testing.T) {
	store := newTestStore()
	var session *recordingAuthSession
	addr := startServer(t, managesieveserver.Options{
		InsecureAuth: true,
		IdleTimeout:  5 * time.Second,
		MaxErrors:    2,
		NewSession: func(conn *managesieveserver.Conn) (managesieveserver.Session, error) {
			base, err := store.NewSession(conn)
			if err != nil {
				return nil, err
			}
			session = &recordingAuthSession{Session: base}
			return session, nil
		},
	})
	c := dial(t, addr)
	c.greet()

	empty := `AUTHENTICATE "PLAIN" "` + base64.StdEncoding.EncodeToString([]byte("\x00user@example.com\x00")) + `"`
	c.send(empty)
	if resp, _ := c.readResponse(); resp != `NO "Refused by the session"` {
		t.Fatalf("AUTHENTICATE with an empty password = %q, want the session's reply", resp)
	}
	session.mu.Lock()
	calls := append([][3]string(nil), session.calls...)
	session.mu.Unlock()
	if len(calls) != 1 || calls[0] != [3]string{"", "user@example.com", ""} {
		t.Fatalf("session saw %q, want one call with (\"\", \"user@example.com\", \"\")", calls)
	}

	// The second refusal exhausts MaxErrors = 2: each counted once.
	c.send(empty)
	if resp, _ := c.readResponse(); resp != `NO "Refused by the session"` {
		t.Fatalf("second AUTHENTICATE = %q", resp)
	}
	if resp, _ := c.readResponse(); resp != `BYE "Too many errors, closing connection"` {
		t.Fatalf("max errors notice = %q", resp)
	}
}
