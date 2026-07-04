package managesieveserver

import (
	"errors"
	"strings"

	"github.com/migadu/go-managesieve/managesieve"
)

// ErrCloseConnection may be returned (or wrapped, via fmt.Errorf("%w", ...))
// by a Session method to instruct the library to send the error's NO response
// and then close the connection. Use it to implement "respond then drop"
// behaviour without leaving the session open.
//
// When ErrCloseConnection is returned bare, a generic "internal error" text
// is sent to the client. To control the wire message, return an *Error with
// Close set to true instead.
var ErrCloseConnection = errors.New("managesieveserver: close connection")

// ErrSilentReject may be returned (or wrapped) by Options.NewSession to reject
// a connection without writing any response: the connection is closed
// immediately, before the greeting. Use it for abuse-control rejections
// (per-IP connection limits, blocklists) where emitting a banner would inform
// or reward the abuser; return any other error to reject with a NO response.
var ErrSilentReject = errors.New("managesieveserver: silently reject connection")

// Error is a Session error whose response is sent to the client and which can
// request connection closure. Unlike a plain error (whose text is forwarded
// as-is after "NO "), an *Error gives the session explicit control over the
// RFC 5804 response code and message and guarantees no internal error string
// leaks onto the wire.
//
//	return &managesieveserver.Error{Code: "NONEXISTENT", Message: "Script does not exist"}
//	// wire: NO (NONEXISTENT) "Script does not exist"
//
//	return &managesieveserver.Error{Message: "Authentication failed", Close: true}
//	// wire: NO Authentication failed   (then the connection is closed)
//
// Rendering rules:
//   - Code set: `NO (CODE) "message"` — the message is sanitized and emitted
//     as a quoted string, per the RFC 5804 §1.3 response-code form.
//   - Code empty: `NO message` — the message is emitted verbatim (CR/LF
//     stripped), so a session that wants RFC framing pre-quotes it with
//     managesieve.Quote. This lets embedders keep byte-exact response texts.
type Error struct {
	// Code is the optional RFC 5804 §1.3 response code, without parentheses
	// (e.g. "NONEXISTENT", "ALREADYEXISTS", "ACTIVE", "TRYLATER",
	// "QUOTA/MAXSIZE", "QUOTA/MAXSCRIPTS", "UNAVAILABLE"). Empty for no code.
	Code string

	// Message is the human-readable message. If empty, "internal error"
	// is used so nothing sensitive is ever emitted by default.
	Message string

	// Close, when true, causes the connection to be closed after the
	// response is flushed.
	Close bool
}

// Error implements the error interface.
func (e *Error) Error() string { return e.wireMessage() }

// wireMessage renders the text that follows "NO " on the wire.
func (e *Error) wireMessage() string {
	msg := e.Message
	if msg == "" {
		msg = "internal error"
	}
	if e.Code == "" {
		return stripCRLF(msg)
	}
	return "(" + strings.ToUpper(e.Code) + ") " + managesieve.Quote(managesieve.SanitizeText(msg))
}

// stripCRLF removes CR and LF from a session-supplied string before it is
// written into a response line, so it cannot smuggle extra response lines
// onto the wire. The common case (no CR/LF present) allocates nothing.
func stripCRLF(s string) string {
	if !strings.ContainsAny(s, "\r\n") {
		return s
	}
	return strings.NewReplacer("\r", "", "\n", "").Replace(s)
}
