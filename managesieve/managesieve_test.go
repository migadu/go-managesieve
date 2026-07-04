package managesieve

import (
	"strings"
	"testing"
)

// TestQuote verifies RFC 5804 quoted-string escaping so an embedded
// double-quote or backslash in a script name / tag cannot break response
// framing.
func TestQuote(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{``, `""`},
		{`inbox`, `"inbox"`},
		{`my"script`, `"my\"script"`},
		{`back\slash`, `"back\\slash"`},
		{`a"b\c`, `"a\"b\\c"`},
		{`\"`, `"\\\""`},
	}
	for _, c := range cases {
		if got := Quote(c.in); got != c.want {
			t.Errorf("Quote(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// TestSanitizeText verifies control characters are neutralized so
// attacker-influenced text (e.g. Sieve validation errors echoing script
// tokens) cannot inject response lines.
func TestSanitizeText(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"plain text", "plain text"},
		{"line1\r\nline2", "line1  line2"},
		{"nul\x00byte", "nul byte"},
		{"del\x7fbyte", "del byte"},
		{"tab\tseparated", "tab separated"},
	}
	for _, c := range cases {
		if got := SanitizeText(c.in); got != c.want {
			t.Errorf("SanitizeText(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// TestValidateScriptName verifies RFC 5804 §1.6 script-name hygiene.
func TestValidateScriptName(t *testing.T) {
	valid := []string{"vacation", "my script", "üñïçödé", "a"}
	for _, name := range valid {
		if err := ValidateScriptName(name); err != nil {
			t.Errorf("ValidateScriptName(%q) = %v, want nil", name, err)
		}
	}

	invalid := map[string]string{
		"":                 "empty",
		"\xff\xfe":         "invalid UTF-8",
		"line\r\nbreak":    "control characters",
		"nul\x00byte":      "control characters",
		"del\x7fcharacter": "control characters",
	}
	for name, why := range invalid {
		if err := ValidateScriptName(name); err == nil {
			t.Errorf("ValidateScriptName(%q) = nil, want error (%s)", name, why)
		}
	}
}

func TestFilterExtensions(t *testing.T) {
	valid, invalid := FilterExtensions([]string{"fileinto", "vacation", "bogus-ext", "variables"})
	if len(valid) != 3 || valid[0] != "fileinto" || valid[1] != "vacation" || valid[2] != "variables" {
		t.Errorf("valid = %v, want [fileinto vacation variables]", valid)
	}
	if len(invalid) != 1 || invalid[0] != "bogus-ext" {
		t.Errorf("invalid = %v, want [bogus-ext]", invalid)
	}

	valid, invalid = FilterExtensions(nil)
	if valid != nil || invalid != nil {
		t.Errorf("FilterExtensions(nil) = %v, %v, want nil, nil", valid, invalid)
	}
}

func TestDefaultEnabledExtensionsAreSupported(t *testing.T) {
	_, invalid := FilterExtensions(DefaultEnabledExtensions)
	if len(invalid) > 0 {
		t.Errorf("DefaultEnabledExtensions contains unsupported entries: %v", invalid)
	}
	// The defaults deliberately exclude security-sensitive extensions.
	for _, ext := range DefaultEnabledExtensions {
		if ext == "editheader" {
			t.Error("DefaultEnabledExtensions must not include editheader")
		}
	}
}

func TestGetSieveCapabilities(t *testing.T) {
	in := []string{"fileinto", "vacation"}
	got := GetSieveCapabilities(in)
	if strings.Join(got, " ") != "fileinto vacation" {
		t.Errorf("GetSieveCapabilities = %v", got)
	}
	// Must be a copy: mutating the result must not affect the input.
	got[0] = "mutated"
	if in[0] != "fileinto" {
		t.Error("GetSieveCapabilities must return a copy")
	}
}
