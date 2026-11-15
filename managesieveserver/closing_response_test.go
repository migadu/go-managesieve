package managesieveserver_test

import (
	"context"
	"errors"
	"fmt"
	"io"
	"testing"
	"time"

	"github.com/migadu/go-managesieve/managesieveserver"
)

// A refused connection has no session to continue with, so the response must
// announce the hang-up rather than look like a recoverable command failure.
func TestNewSessionRefusalSendsBye(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
		want string
	}{
		{"plain", errors.New("private backend failure"), `BYE "Service not available"`},
		{"coded", &managesieveserver.Error{Code: "TRYLATER", Message: "Too many connections"}, `BYE (TRYLATER) "Too many connections"`},
		{"wrapped coded", fmt.Errorf("backend: %w", &managesieveserver.Error{Code: "TRYLATER", Message: "Too many connections"}), `BYE (TRYLATER) "Too many connections"`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			addr := startServer(t, managesieveserver.Options{
				NewSession: func(*managesieveserver.Conn) (managesieveserver.Session, error) {
					return nil, tc.err
				},
			})
			assertClosingResponse(t, dial(t, addr), tc.want)
		})
	}
}

type closingResponseSession struct {
	managesieveserver.Session
	authErr  error
	checkErr error
}

func (s *closingResponseSession) AuthenticatePlain(ctx context.Context, identity, username, password string) error {
	if s.authErr != nil {
		return s.authErr
	}
	return s.Session.AuthenticatePlain(ctx, identity, username, password)
}

func (s *closingResponseSession) CheckScript(ctx context.Context, content string) (string, error) {
	return "", s.checkErr
}

func TestSessionClosingErrorSendsBye(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
		want string
	}{
		{"coded", &managesieveserver.Error{Code: "TRYLATER", Message: "Session closed", Close: true}, `BYE (TRYLATER) "Session closed"`},
		{"uncoded", &managesieveserver.Error{Message: `"Session closed"`, Close: true}, `BYE "Session closed"`},
		{"wrapped typed", fmt.Errorf("backend: %w", &managesieveserver.Error{Code: "TRYLATER", Message: "Session closed", Close: true}), `BYE (TRYLATER) "Session closed"`},
		{"sentinel", managesieveserver.ErrCloseConnection, `BYE "internal error"`},
		{"wrapped sentinel", fmt.Errorf("private backend failure: %w", managesieveserver.ErrCloseConnection), `BYE "internal error"`},
		{"joined coded sentinel", errors.Join(&managesieveserver.Error{Code: "TRYLATER", Message: "Session closed"}, managesieveserver.ErrCloseConnection), `BYE (TRYLATER) "Session closed"`},
	} {
		for _, command := range []string{"AUTHENTICATE", "CHECKSCRIPT"} {
			t.Run(tc.name+"/"+command, func(t *testing.T) {
				store := newTestStore()
				addr := startServer(t, managesieveserver.Options{
					InsecureAuth: true,
					MaxErrors:    1,
					NewSession: func(conn *managesieveserver.Conn) (managesieveserver.Session, error) {
						base, err := store.NewSession(conn)
						if err != nil {
							return nil, err
						}
						session := &closingResponseSession{Session: base, checkErr: tc.err}
						if command == "AUTHENTICATE" {
							session.authErr = tc.err
						}
						return session, nil
					},
				})
				c := dial(t, addr)
				if command == "AUTHENTICATE" {
					c.greet()
					// SASL PLAIN: empty authzid, user@example.com, secret.
					c.send(`AUTHENTICATE "PLAIN" "AHVzZXJAZXhhbXBsZS5jb20Ac2VjcmV0"`)
				} else {
					c.authenticate("user@example.com", "secret")
					c.send(`CHECKSCRIPT "keep;"`)
				}
				assertClosingResponse(t, c, tc.want)
			})
		}
	}
}

func TestNonClosingSessionErrorRemainsNo(t *testing.T) {
	store := newTestStore()
	addr := startServer(t, managesieveserver.Options{
		InsecureAuth: true,
		NewSession: func(conn *managesieveserver.Conn) (managesieveserver.Session, error) {
			base, err := store.NewSession(conn)
			if err != nil {
				return nil, err
			}
			return &closingResponseSession{
				Session:  base,
				checkErr: &managesieveserver.Error{Code: "TRYLATER", Message: "Try again"},
			}, nil
		},
	})
	c := dial(t, addr)
	c.authenticate("user@example.com", "secret")
	c.send(`CHECKSCRIPT "keep;"`)
	if line, err := c.r.ReadString('\n'); err != nil || line != "NO (TRYLATER) \"Try again\"\r\n" {
		t.Fatalf("non-closing response = %q, %v", line, err)
	}
	c.send("NOOP")
	if response, _ := c.readResponse(); response != "OK" {
		t.Fatalf("NOOP after non-closing error = %q, want OK", response)
	}
}

func assertClosingResponse(t *testing.T, c *client, want string) {
	t.Helper()
	if err := c.conn.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if line, err := c.r.ReadString('\n'); err != nil || line != want+"\r\n" {
		t.Errorf("closing response = %q, %v; want %q", line, err, want+"\r\n")
	}
	if line, err := c.r.ReadString('\n'); line != "" || !errors.Is(err, io.EOF) {
		t.Errorf("after closing response = %q, %v; want empty EOF", line, err)
	}
}
