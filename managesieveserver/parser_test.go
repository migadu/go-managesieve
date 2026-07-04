package managesieveserver

import (
	"bufio"
	"errors"
	"strings"
	"testing"
)

func TestParseLine(t *testing.T) {
	tests := []struct {
		in      string
		cmd     string
		args    []string
		wantErr bool
	}{
		{``, ``, nil, false},
		{`NOOP`, `NOOP`, nil, false},
		{`noop`, `NOOP`, nil, false},
		{`GETSCRIPT "my script"`, `GETSCRIPT`, []string{`"my script"`}, false},
		{`PUTSCRIPT "name" {123+}`, `PUTSCRIPT`, []string{`"name"`, `{123+}`}, false},
		{`AUTHENTICATE "PLAIN" "dGVzdA=="`, `AUTHENTICATE`, []string{`"PLAIN"`, `"dGVzdA=="`}, false},
		{`RENAMESCRIPT "a \"quoted\" name" "plain"`, `RENAMESCRIPT`, []string{`"a \"quoted\" name"`, `"plain"`}, false},
		{`GETSCRIPT "unclosed`, `GETSCRIPT`, nil, true},
	}
	for _, tt := range tests {
		cmd, args, err := parseLine(tt.in)
		if (err != nil) != tt.wantErr {
			t.Errorf("parseLine(%q) err = %v, wantErr %v", tt.in, err, tt.wantErr)
			continue
		}
		if err != nil {
			continue
		}
		if cmd != tt.cmd {
			t.Errorf("parseLine(%q) cmd = %q, want %q", tt.in, cmd, tt.cmd)
		}
		if len(args) != len(tt.args) {
			t.Errorf("parseLine(%q) args = %v, want %v", tt.in, args, tt.args)
			continue
		}
		for i := range args {
			if args[i] != tt.args[i] {
				t.Errorf("parseLine(%q) args[%d] = %q, want %q", tt.in, i, args[i], tt.args[i])
			}
		}
	}
}

func TestUnquoteString(t *testing.T) {
	tests := []struct{ in, want string }{
		{`"hello"`, `hello`},
		{`hello`, `hello`},
		{`""`, ``},
		{`"a \"b\" c"`, `a "b" c`},
		{`"back\\slash"`, `back\slash`},
		{`"`, `"`},       // too short to be quoted
		{`{5+}`, `{5+}`}, // literal markers pass through
	}
	for _, tt := range tests {
		if got := unquoteString(tt.in); got != tt.want {
			t.Errorf("unquoteString(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestLiteralLength(t *testing.T) {
	tests := []struct {
		in      string
		length  int64
		nonSync bool
		isLit   bool
		wantErr bool
	}{
		{`{10+}`, 10, true, true, false},
		{`{100}`, 100, false, true, false},
		{`{0+}`, 0, true, true, false},
		{`{abc}`, 0, false, true, true},
		{`{-1}`, 0, false, true, true},
		{`{99999999999999999999}`, 0, false, true, true}, // overflow
		{`"quoted"`, 0, false, false, false},
		{`atom`, 0, false, false, false},
		{`10+}`, 0, false, false, false},
	}
	for _, tt := range tests {
		length, nonSync, isLit, err := literalLength(tt.in)
		if isLit != tt.isLit {
			t.Errorf("literalLength(%q) isLit = %v, want %v", tt.in, isLit, tt.isLit)
			continue
		}
		if !isLit {
			continue
		}
		if (err != nil) != tt.wantErr {
			t.Errorf("literalLength(%q) err = %v, wantErr %v", tt.in, err, tt.wantErr)
			continue
		}
		if err != nil {
			continue
		}
		if length != tt.length || nonSync != tt.nonSync {
			t.Errorf("literalLength(%q) = (%d, %v), want (%d, %v)", tt.in, length, nonSync, tt.length, tt.nonSync)
		}
	}
}

func TestReadBoundedLine(t *testing.T) {
	// Within bounds.
	r := bufio.NewReader(strings.NewReader("hello\r\nworld\r\n"))
	line, err := readBoundedLine(r, 100)
	if err != nil || strings.TrimSpace(line) != "hello" {
		t.Errorf("readBoundedLine = %q, %v", line, err)
	}

	// Oversized line is rejected and drained so the next line is readable.
	long := strings.Repeat("x", 200) + "\r\nnext\r\n"
	r = bufio.NewReader(strings.NewReader(long))
	_, err = readBoundedLine(r, 50)
	if !errors.Is(err, errLineTooLong) {
		t.Errorf("expected errLineTooLong, got %v", err)
	}
	line, err = readBoundedLine(r, 50)
	if err != nil || strings.TrimSpace(line) != "next" {
		t.Errorf("after oversize: readBoundedLine = %q, %v (drain failed)", line, err)
	}
}
