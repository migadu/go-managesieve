package managesieveserver_test

import (
	"fmt"
	"testing"
)

// plainUserSecret is the SASL PLAIN response for user@example.com with
// password "secret" ("\x00user@example.com\x00secret"), which newTestStore
// accepts.
const plainUserSecret = "AHVzZXJAZXhhbXBsZS5jb20Ac2VjcmV0"

// A SASL response that is not pure base64 must be refused, never decoded with
// the offending characters skipped or trimmed. RFC 5804 section 2.1: "A client
// response consists of a string (quoted or literal) with the base-64 encoding
// of the SASL data followed by a CRLF", where base-64 is RFC 4648, whose
// section 3.3 says: "Implementations MUST reject the encoded data if it
// contains characters outside the base alphabet when interpreting
// base-encoded data". Go's base64.StdEncoding skips CR and LF anywhere in its
// input, so valid credentials with a CR or CRLF spliced in, or with
// whitespace around them, used to log the client in.
func TestAuthenticateRefusesNonBase64Characters(t *testing.T) {
	literal := func(s string) string { return fmt.Sprintf("{%d+}\r\n%s", len(s), s) }
	crInside := plainUserSecret[:4] + "\r" + plainUserSecret[4:]
	crlfInside := plainUserSecret[:4] + "\r\n" + plainUserSecret[4:]
	backslashInside := plainUserSecret[:4] + `\` + plainUserSecret[4:]

	tests := []struct {
		name         string
		initial      bool   // the response is the AUTHENTICATE initial response
		response     string // sent as is, followed by CRLF
		wantRejected bool
	}{
		{"initial quoted", true, `"` + plainUserSecret + `"`, false},
		{"initial quoted, CR inside", true, `"` + crInside + `"`, true},
		{"initial quoted, space inside", true, `"` + plainUserSecret[:4] + " " + plainUserSecret[4:] + `"`, true},
		{"initial literal", true, literal(plainUserSecret), false},
		{"initial literal, CR inside", true, literal(crInside), true},
		{"initial literal, CRLF inside", true, literal(crlfInside), true},
		{"initial literal, CR at the end", true, literal(plainUserSecret + "\r"), true},
		// An unquoted initial response is not a string, but it is accepted
		// like a bare continuation line, and like one it runs to the CRLF:
		// whitespace or a CR before the CRLF is part of it.
		{"initial atom", true, plainUserSecret, false},
		{"initial atom, CR before the CRLF", true, plainUserSecret + "\r", true},
		{"initial atom, trailing space", true, plainUserSecret + " ", true},
		{"initial atom, trailing tab", true, plainUserSecret + "\t", true},
		// A quoted initial response is a command argument, refused by the
		// command parser when it holds an invalid escape such as "\" before a
		// base64 character (TestInvalidQuotedEscapeRefused). An escaped
		// backslash is a valid QUOTED-CHAR, but outside the base64 alphabet.
		{"initial quoted, escaped backslash inside", true, `"` + plainUserSecret[:4] + `\\` + plainUserSecret[4:] + `"`, true},

		{"continuation bare", false, plainUserSecret, false},
		{"continuation bare, CR inside", false, crInside, true},
		{"continuation bare, CR before the CRLF", false, plainUserSecret + "\r", true},
		{"continuation bare, leading space", false, " " + plainUserSecret, true},
		{"continuation bare, trailing space", false, plainUserSecret + " ", true},
		{"continuation quoted", false, `"` + plainUserSecret + `"`, false},
		{"continuation quoted, CR inside", false, `"` + crInside + `"`, true},
		{"continuation quoted, leading space", false, ` "` + plainUserSecret + `"`, true},
		// A backslash is outside the base64 alphabet, and "\" before a
		// base64 character is no QUOTED-CHAR either (RFC 5804 section 4:
		// QUOTED-CHAR = SAFE-UTF8-CHAR / "\" QUOTED-SPECIALS).
		{"continuation quoted, backslash inside", false, `"` + backslashInside + `"`, true},
		{"continuation literal", false, literal(plainUserSecret), false},
		{"continuation literal, CRLF inside", false, literal(crlfInside), true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			addr := startDefaultServer(t, newTestStore())
			c := dial(t, addr)
			c.greet()

			if tt.initial {
				c.sendRaw(`AUTHENTICATE "PLAIN" ` + tt.response + "\r\n")
			} else {
				c.send(`AUTHENTICATE "PLAIN"`)
				if line := c.readLine(); line != `""` {
					t.Fatalf("continuation = %q, want %q", line, `""`)
				}
				c.sendRaw(tt.response + "\r\n")
			}
			resp, _ := c.readResponse()
			if !tt.wantRejected {
				if resp != `OK "Authenticated"` {
					t.Fatalf("response %q: got %q, want OK", tt.response, resp)
				}
				return
			}
			if resp != `NO "Invalid authentication data"` {
				t.Fatalf("response %q: got %q, want NO \"Invalid authentication data\"", tt.response, resp)
			}

			// The session is still not authenticated, and the same
			// credentials sent as plain base64 log in on the same connection.
			c.send(`AUTHENTICATE "PLAIN" "` + plainUserSecret + `"`)
			if resp, _ := c.readResponse(); resp != `OK "Authenticated"` {
				t.Fatalf("AUTHENTICATE after the refusal: got %q, want OK", resp)
			}
		})
	}
}

// An unquoted initial response after a literal mechanism name is on the line
// that follows the literal's body, and ends that line like any other.
func TestAuthenticateAtomAfterLiteralMechanism(t *testing.T) {
	tests := []struct {
		name, response string
		want           string
	}{
		{"atom", plainUserSecret, `OK "Authenticated"`},
		{"atom, CR before the CRLF", plainUserSecret + "\r", `NO "Invalid authentication data"`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			addr := startDefaultServer(t, newTestStore())
			c := dial(t, addr)
			c.greet()

			c.sendRaw("AUTHENTICATE {5+}\r\nPLAIN " + tt.response + "\r\n")
			if resp, _ := c.readResponse(); resp != tt.want {
				t.Fatalf("response %q: got %q, want %q", tt.response, resp, tt.want)
			}
		})
	}
}
