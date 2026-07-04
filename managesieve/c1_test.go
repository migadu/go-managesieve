package managesieve

import "testing"

// TestValidateScriptNameRejectsC1Controls: Net-Unicode (RFC 5198, referenced
// by RFC 5804 for script names) prohibits the C1 control range U+0080-U+009F,
// which slips past a C0/DEL-only check because it is valid UTF-8.
func TestValidateScriptNameRejectsC1Controls(t *testing.T) {
	for _, name := range []string{
		"bad\u0080name",
		"bad\u0085name", // NEL, the classic C1 line separator
		"bad\u009fname",
	} {
		if err := ValidateScriptName(name); err == nil {
			t.Errorf("ValidateScriptName(%q) accepted a C1 control character", name)
		}
	}
	// The range boundaries' neighbours stay valid.
	for _, name := range []string{"ok\u007ename", "ok\u00a0name"} {
		if err := ValidateScriptName(name); err != nil {
			t.Errorf("ValidateScriptName(%q) = %v, want nil", name, err)
		}
	}
}
