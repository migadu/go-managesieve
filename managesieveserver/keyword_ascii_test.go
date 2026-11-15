package managesieveserver_test

import (
	"encoding/base64"
	"strings"
	"testing"
)

// Command names and SASL mechanism names are case-insensitive over US-ASCII
// only: RFC 5804 section 4, "Except as noted otherwise, all alphabetic
// characters are case-insensitive", in ABNF, whose "strings are case
// insensitive and the character set for these strings is US-ASCII" (RFC 5234
// section 2.3); RFC 4422 section 3.1 names mechanisms with "ASCII [ASCII]
// uppercase letters, digits, hyphens, and/or underscores". strings.ToUpper
// maps U+0131 (LATIN SMALL LETTER DOTLESS I) to "I" and U+017F (LATIN SMALL
// LETTER LONG S) to "S": a look-alike must be refused as an unknown command or
// mechanism, never executed as the keyword.
func TestKeywordLookalikesAreNotKeywords(t *testing.T) {
	plain := base64.StdEncoding.EncodeToString([]byte("\x00user@example.com\x00secret"))
	tests := []struct {
		name string
		auth bool // authenticate first
		line string
		want string // prefix of the response line
	}{
		{"CAPABILITY with dotless i", false, "CAPABıLITY", "NO"},
		{"AUTHENTICATE with dotless i", false, `AUTHENTıCATE "PLAIN" "` + plain + `"`, "NO"},
		{"mechanism with dotless i", false, `AUTHENTICATE "PLAıN" "` + plain + `"`, "NO"},
		{"LISTSCRIPTS with dotless i", true, "LıSTSCRIPTS", "NO"},
		{"HAVESPACE with long s", true, `HAVEſPACE "s" 10`, "NO"},
		{"SETACTIVE with long s", true, `ſETACTIVE ""`, "NO"},

		// ASCII letters in any case are still the keywords.
		{"lower-case CAPABILITY", false, "capability", "OK"},
		{"lower-case mechanism", false, `authenticate "plain" "` + plain + `"`, "OK"},
		{"lower-case LISTSCRIPTS", true, "listscripts", "OK"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			addr := startDefaultServer(t, newTestStore())
			c := dial(t, addr)
			if tt.auth {
				c.authenticate("user@example.com", "secret")
			} else {
				c.greet()
			}

			c.send(tt.line)
			resp, data := c.readResponse()
			if !strings.HasPrefix(resp, tt.want) {
				t.Fatalf("%s: got %q (data %q), want %q", tt.line, resp, data, tt.want)
			}
			if tt.want != "NO" {
				return
			}
			if len(data) > 0 {
				t.Fatalf("%s: refused with data lines %q", tt.line, data)
			}

			// The connection is still in service.
			c.send("NOOP")
			if resp, _ := c.readResponse(); !strings.HasPrefix(resp, "OK") {
				t.Fatalf("NOOP after %s: got %q", tt.line, resp)
			}
		})
	}
}
