package managesieveserver

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"math"
	"strings"
)

// errLineTooLong is returned by readBoundedLine when a line exceeds the
// configured MaxLineLength. The command loop sends a courtesy
// `NO "Command line too long"` before dropping the connection.
var errLineTooLong = errors.New("managesieveserver: line too long")

// errMissingCRLF is returned by readBoundedLine for a line that is not
// terminated by CRLF (a bare LF, or data cut off by EOF). RFC 5804 frames
// every line with CRLF; a malformed line must never execute. The command
// loop sends a courtesy NO before dropping the connection.
var errMissingCRLF = errors.New("managesieveserver: line not terminated by CRLF")

// parseLine tokenizes a ManageSieve command line into an upper-cased command
// verb and its arguments. It handles space-separated atoms and double-quoted
// strings with backslash escapes (RFC 5804 §1.2). Quoted-string arguments are
// returned with their quotes intact — handlers unquote per-argument via
// unquoteString, because some arguments (literal markers like {12+}) must not
// be unquoted.
func parseLine(line string) (command string, args []string, err error) {
	line = strings.TrimSpace(line)
	if line == "" {
		return "", nil, nil
	}

	parts := strings.SplitN(line, " ", 2)
	command = strings.ToUpper(parts[0])
	if len(parts) < 2 {
		return command, nil, nil
	}
	args, err = parseTokens(strings.TrimSpace(parts[1]))
	return command, args, err
}

// parseTokens tokenizes command arguments: space-separated atoms and
// double-quoted strings with backslash escapes. It is used for the argument
// part of a command line and for the continuation of a command after a
// literal argument's body.
func parseTokens(rem string) (args []string, err error) {
	for rem != "" {
		rem = strings.TrimSpace(rem)
		if rem == "" {
			break
		}

		var arg string
		if rem[0] == '"' {
			// Quoted string - find closing quote, respecting escape
			// sequences: characters inside quotes can be escaped with
			// backslash.
			i := 1
			escaped := false
			found := false
			for i < len(rem) {
				if escaped {
					escaped = false
					i++
					continue
				}
				if rem[i] == '\\' {
					escaped = true
					i++
					continue
				}
				if rem[i] == '"' {
					// Found unescaped closing quote
					arg = rem[:i+1]
					rem = rem[i+1:]
					found = true
					break
				}
				i++
			}
			if !found {
				return nil, fmt.Errorf("unclosed quote in command arguments")
			}
		} else {
			// Atom
			end := strings.Index(rem, " ")
			if end == -1 {
				arg = rem
				rem = ""
			} else {
				arg = rem[:end]
				rem = rem[end:]
			}
		}
		args = append(args, arg)
	}

	return args, nil
}

// unquoteString removes surrounding double quotes from a string if present
// and processes backslash escape sequences. Strings without surrounding
// quotes are returned unchanged.
func unquoteString(str string) string {
	if len(str) < 2 || str[0] != '"' || str[len(str)-1] != '"' {
		return str
	}

	// Remove surrounding quotes
	inner := str[1 : len(str)-1]

	// Process escape sequences
	var result strings.Builder
	result.Grow(len(inner))
	escaped := false
	for i := 0; i < len(inner); i++ {
		if escaped {
			result.WriteByte(inner[i])
			escaped = false
		} else if inner[i] == '\\' {
			escaped = true
		} else {
			result.WriteByte(inner[i])
		}
	}

	return result.String()
}

// readBoundedLine reads a line from the reader up to maxBytes. Returns
// errLineTooLong if the line (including \n) exceeds maxBytes; the oversized
// line is drained so the error can be reported before the connection is torn
// down. The returned line includes the trailing \n if present.
func readBoundedLine(reader *bufio.Reader, maxBytes int) (string, error) {
	var line []byte
	for {
		chunk, err := reader.ReadSlice('\n')
		line = append(line, chunk...)

		// Check if we've exceeded the limit
		if len(line) > maxBytes {
			if err == nil {
				// Found \n and already exceeded limit
				return "", errLineTooLong
			}
			if err == bufio.ErrBufferFull {
				// Keep draining until we find \n or EOF
				for {
					_, drainErr := reader.ReadSlice('\n')
					if drainErr == nil {
						return "", errLineTooLong
					}
					if drainErr != bufio.ErrBufferFull {
						return "", errLineTooLong
					}
				}
			}
			// EOF or other error while over limit - line is too long
			return "", errLineTooLong
		}

		// Within limit - check if we're done
		if err == nil {
			// Strict framing: the terminator must be CRLF, not a bare LF.
			if len(line) < 2 || line[len(line)-2] != '\r' {
				return "", errMissingCRLF
			}
			return string(line), nil
		}

		if err == bufio.ErrBufferFull {
			continue
		}

		// EOF or other error
		if err == io.EOF {
			if len(line) > 0 {
				// Data cut off by EOF without a terminator: not a
				// well-formed line, so it must never execute.
				return "", errMissingCRLF
			}
			return "", io.EOF
		}

		return "", err
	}
}

// literalLength parses a ManageSieve literal marker ({N} or {N+}) and
// returns its declared length together with whether the literal is
// non-synchronizing ({N+}). ok is false when arg is not a literal marker at
// all; err is non-nil when it looks like a literal but the length is invalid.
func literalLength(arg string) (length int64, nonSync bool, ok bool, err error) {
	if !strings.HasPrefix(arg, "{") || !strings.HasSuffix(arg, "}") {
		return 0, false, false, nil
	}
	nonSync = strings.HasSuffix(arg, "+}")

	lengthStr := strings.TrimPrefix(arg, "{")
	lengthStr = strings.TrimSuffix(lengthStr, "}")
	lengthStr = strings.TrimSuffix(lengthStr, "+")

	length, perr := parseInt64(lengthStr)
	if perr != nil {
		return 0, nonSync, true, perr
	}
	return length, nonSync, true, nil
}

// parseInt64 parses a non-negative decimal integer, rejecting anything that
// is not all-digits or that would overflow int64.
func parseInt64(s string) (int64, error) {
	if len(s) == 0 {
		return 0, errors.New("not a number")
	}
	const maxVal = int64(math.MaxInt64)
	var n int64
	for _, ch := range s {
		if ch < '0' || ch > '9' {
			return 0, errors.New("not a number")
		}
		if n > (maxVal-int64(ch-'0'))/10 {
			return 0, errors.New("number too large")
		}
		n = n*10 + int64(ch-'0')
	}
	return n, nil
}
