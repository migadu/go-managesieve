package managesieveserver_test

import (
	"encoding/base64"
	"fmt"
	"strings"
	"testing"
)

// In a quoted string a backslash may only escape DQUOTE or another
// backslash. RFC 5804 section 4:
//
//	quoted          = DQUOTE *1024QUOTED-CHAR DQUOTE
//	QUOTED-CHAR     = SAFE-UTF8-CHAR / "\" QUOTED-SPECIALS
//	QUOTED-SPECIALS = DQUOTE / "\"
//
// and SAFE-CHAR excludes the backslash itself. "a\b" is therefore no quoted
// string: the command must be refused as a syntax error and not run, where
// the backslash used to be dropped and the command run on "ab".
func TestInvalidQuotedEscapeRefused(t *testing.T) {
	plain := base64.StdEncoding.EncodeToString([]byte("\x00user@example.com\x00secret"))
	// A literal body that is a command, run if the body is misread as one.
	const smuggled = "DELETESCRIPT ab"
	tests := []struct {
		name   string
		auth   bool   // authenticate first
		send   string // sent as is
		closes bool   // the refused line committed a {N+} literal body
	}{
		{"PUTSCRIPT name", true, "PUTSCRIPT \"a\\b\" \"keep;\"\r\n", false},
		{"PUTSCRIPT content", true, "PUTSCRIPT \"new\" \"kee\\p;\"\r\n", false},
		{"CHECKSCRIPT content", true, "CHECKSCRIPT \"kee\\p;\"\r\n", false},
		{"GETSCRIPT", true, "GETSCRIPT \"a\\b\"\r\n", false},
		{"SETACTIVE", true, "SETACTIVE \"a\\b\"\r\n", false},
		{"DELETESCRIPT", true, "DELETESCRIPT \"a\\b\"\r\n", false},
		{"RENAMESCRIPT old name", true, "RENAMESCRIPT \"a\\b\" \"new\"\r\n", false},
		{"RENAMESCRIPT new name", true, "RENAMESCRIPT \"ab\" \"ne\\w\"\r\n", false},
		{"HAVESPACE", true, "HAVESPACE \"a\\b\" 10\r\n", false},
		{"NOOP tag", true, "NOOP \"ta\\g\"\r\n", false},
		{"escape before a non-ASCII character", true, "GETSCRIPT \"a\\\u00e9b\"\r\n", false},
		{"AUTHENTICATE mechanism", false, "AUTHENTICATE \"PL\\AIN\" \"" + plain + "\"\r\n", false},
		{"AUTHENTICATE initial response", false, "AUTHENTICATE \"PLAIN\" \"" + plain[:4] + "\\" + plain[4:] + "\"\r\n", false},
		{"LOGIN password", false, "LOGIN \"user@example.com\" \"secr\\et\"\r\n", false},

		// The rest of a command line after a literal argument is parsed
		// like the line itself.
		{"after a literal argument", true, "RENAMESCRIPT {2+}\r\nab \"ne\\w\"\r\n", false},

		// A refused line that ends with a non-synchronizing literal has
		// committed the literal's body, which must not then be read as
		// commands: the connection is closed after the NO, as for a literal
		// refused for its size. A synchronizing literal gets no "+"
		// continuation, so its body is never sent.
		{"PUTSCRIPT name, non-sync literal content", true, fmt.Sprintf("PUTSCRIPT \"a\\b\" {%d+}\r\n%s\r\n", len(smuggled), smuggled), true},
		{"PUTSCRIPT name, sync literal content", true, fmt.Sprintf("PUTSCRIPT \"a\\b\" {%d}\r\n", len(smuggled)), false},
		{"AUTHENTICATE mechanism, literal response", false, fmt.Sprintf("AUTHENTICATE \"PL\\AIN\" {%d+}\r\n%s\r\n", len(plain), plain), true},
		{"after a literal argument, non-sync literal", true, fmt.Sprintf("RENAMESCRIPT {2+}\r\nab \"ne\\w\" {%d+}\r\n%s\r\n", len(smuggled), smuggled), true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := newTestStore()
			store.AddScript("user@example.com", "ab", "keep;", false)
			addr := startDefaultServer(t, store)
			c := dial(t, addr)
			if tt.auth {
				c.authenticate("user@example.com", "secret")
			} else {
				c.greet()
			}

			c.sendRaw(tt.send)
			resp, data := c.readResponse()
			if !strings.HasPrefix(resp, `NO "Invalid command syntax:`) {
				t.Fatalf("%q: got %q (data %q), want NO \"Invalid command syntax: ...\"", tt.send, resp, data)
			}
			if len(data) > 0 {
				t.Fatalf("%q: refused with data lines %q", tt.send, data)
			}

			switch {
			case tt.closes:
				if line, err := c.r.ReadString('\n'); err == nil {
					t.Fatalf("%q: connection still open after the refusal, got %q", tt.send, line)
				}
				c = dial(t, addr)
				c.authenticate("user@example.com", "secret")
			case !tt.auth:
				// Not logged in: the same credentials still log in on
				// the same connection.
				c.send(`AUTHENTICATE "PLAIN" "` + plain + `"`)
				if resp, _ := c.readResponse(); resp != `OK "Authenticated"` {
					t.Fatalf("AUTHENTICATE after the refusal: got %q, want OK", resp)
				}
			}

			// Nothing was stored, renamed, activated or deleted.
			c.send("LISTSCRIPTS")
			resp, data = c.readResponse()
			if resp != "OK" || len(data) != 1 || data[0] != `"ab"` {
				t.Fatalf("LISTSCRIPTS after %q: got %q %q, want OK [\"ab\"]", tt.send, resp, data)
			}
		})
	}
}

// The two escapes RFC 5804 section 4 allows still work in every quoted
// argument position.
func TestValidQuotedEscapesAccepted(t *testing.T) {
	store := newTestStore()
	addr := startDefaultServer(t, store)
	c := dial(t, addr)
	c.authenticate("user@example.com", "secret")

	for _, step := range []struct{ send, want string }{
		{`PUTSCRIPT "a\\b" "keep;"`, `OK "Script stored"`},
		{`PUTSCRIPT "a\"b" "keep;"`, `OK "Script stored"`},
		{`RENAMESCRIPT "a\"b" "c\\d"`, "OK"},
		{`SETACTIVE "a\\b"`, "OK"},
		{`HAVESPACE "a\\b" 10`, "OK"},
		{`CHECKSCRIPT "keep; # \"\\"`, "OK"},
	} {
		c.send(step.send)
		if resp, data := c.readResponse(); resp != step.want {
			t.Fatalf("%s: got %q (data %q), want %q", step.send, resp, data, step.want)
		}
	}

	c.send("LISTSCRIPTS")
	resp, data := c.readResponse()
	if resp != "OK" || strings.Join(data, ",") != `"a\\b" ACTIVE,"c\\d"` {
		t.Fatalf("LISTSCRIPTS: got %q %q", resp, data)
	}
	c.send(`GETSCRIPT "c\\d"`)
	if resp, data := c.readResponse(); resp != "OK" || len(data) < 2 || data[1] != "keep;" {
		t.Fatalf(`GETSCRIPT "c\\d": got %q %q`, resp, data)
	}
}
