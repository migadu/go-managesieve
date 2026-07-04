// Package managesieve provides shared wire types and helpers for the
// ManageSieve protocol (RFC 5804), used by both the server
// (managesieveserver) and client (managesieveclient) packages.
package managesieve

import (
	"fmt"
	"strings"
	"unicode/utf8"
)

// ScriptInfo describes one script in a LISTSCRIPTS response.
type ScriptInfo struct {
	// Name is the script name (unquoted).
	Name string

	// Active reports whether this is the active script. At most one script
	// per account may be active.
	Active bool
}

// Capability is one additional capability line advertised in the greeting
// and CAPABILITY responses, beyond the built-ins the server emits itself
// (IMPLEMENTATION, VERSION, SIEVE, STARTTLS, SASL, MAXSCRIPTSIZE).
type Capability struct {
	// Name is the capability name (e.g. "NOTIFY", "OWNER", "LANGUAGE").
	Name string

	// Value is the capability value, rendered as a quoted string when
	// HasValue is set.
	Value string

	// HasValue selects between `"NAME" "VALUE"` (true) and a name-only
	// `"NAME"` line (false).
	HasValue bool
}

// Quote renders s as a ManageSieve quoted string (RFC 5804 §1.2), escaping
// backslash and double-quote so an embedded quote in a script name or client
// tag cannot break response framing.
func Quote(s string) string {
	s = strings.ReplaceAll(s, "\\", "\\\\")
	s = strings.ReplaceAll(s, "\"", "\\\"")
	return "\"" + s + "\""
}

// SanitizeText neutralizes control characters (CR, LF, NUL and other C0/DEL
// bytes) in server-supplied human-readable text — e.g. SIEVE validation
// errors that echo attacker-controlled script tokens — so it cannot inject a
// forged response line when embedded in a NO/OK response. Pair with Quote for
// RFC 5804 framing.
func SanitizeText(s string) string {
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, s)
}

// ValidateScriptName enforces basic ManageSieve script-name hygiene (RFC 5804
// §1.6: names are UTF-8 Net-Unicode strings). Rejects empty names, invalid
// UTF-8, and control characters — C0/DEL and the C1 range U+0080–U+009F,
// which RFC 5198 prohibits and which have no legitimate use and could corrupt
// logs or LISTSCRIPTS/GETSCRIPT output.
func ValidateScriptName(name string) error {
	if name == "" {
		return fmt.Errorf("script name cannot be empty")
	}
	if !utf8.ValidString(name) {
		return fmt.Errorf("script name must be valid UTF-8")
	}
	for _, r := range name {
		if r < 0x20 || r == 0x7f || (r >= 0x80 && r <= 0x9f) {
			return fmt.Errorf("script name must not contain control characters")
		}
	}
	return nil
}
