package managesieve

// SupportedExtensions lists the SIEVE extensions a typical Sieve interpreter
// (github.com/migadu/go-sieve) can validate and execute. It is the default
// vocabulary used by FilterExtensions to reject unknown extension names in a
// server's configuration.
//
// NOTE: Core RFC 5228 commands (require, if/elsif/else, stop, redirect, keep,
// discard) are always available and don't need to be in this list.
//
// The library itself never validates Sieve scripts — validation is the host
// application's responsibility (see managesieveserver.Session) — so this list
// only drives capability advertisement and configuration filtering.
var SupportedExtensions = []string{
	// Core extensions from RFC 5228
	"fileinto",          // RFC 5228 - Store messages in specified mailbox
	"envelope",          // RFC 5228 - Test envelope addresses
	"encoded-character", // RFC 5228 - Encoded character support

	// Comparators
	"comparator-i;octet",           // RFC 4790 - Octet comparator
	"comparator-i;ascii-casemap",   // RFC 4790 - ASCII case-insensitive
	"comparator-i;ascii-numeric",   // RFC 4790 - ASCII numeric
	"comparator-i;unicode-casemap", // RFC 4790 - Unicode case-insensitive

	// Common extensions
	"imap4flags", // RFC 5232 - IMAP flag manipulation
	"variables",  // RFC 5229 - Variable support
	"relational", // RFC 5231 - Relational tests (gt, lt, etc.)
	"vacation",   // RFC 5230 - Vacation auto-responder
	"copy",       // RFC 3894 - Copy extension for redirect and fileinto
	"regex",      // draft-murchison-sieve-regex - Regular expression match type
	"date",       // RFC 5260 - Date and index extensions - date test
	"index",      // RFC 5260 - Date and index extensions - header indexing
	"mailbox",    // RFC 5490 - Mailbox existence test
	"subaddress", // RFC 5233 - Subaddress extension (user+detail@domain)
	"body",       // RFC 5173 - Body extension

	// Security-sensitive extensions (available but not enabled by default)
	"editheader", // RFC 5293 - Editheader extension - add/delete headers
}

// DefaultEnabledExtensions is the safe subset of extensions enabled by default.
// Excludes security-sensitive extensions like editheader.
var DefaultEnabledExtensions = []string{
	// Core extensions from RFC 5228
	"fileinto",
	"envelope",
	"encoded-character",

	// Comparators
	"comparator-i;octet",
	"comparator-i;ascii-casemap",
	"comparator-i;ascii-numeric",
	"comparator-i;unicode-casemap",

	// Common extensions
	"imap4flags",
	"variables",
	"relational",
	"vacation",
	"copy",
	"regex",
	"date",
	"index",
	"mailbox",
	"subaddress",
	"body",
}

// FilterExtensions checks the provided extensions against SupportedExtensions.
// Returns a slice of valid extensions and a slice of invalid extensions.
func FilterExtensions(extensions []string) (valid []string, invalid []string) {
	if len(extensions) == 0 {
		return nil, nil
	}

	// Build map of all supported extensions
	supportedMap := make(map[string]bool)
	for _, ext := range SupportedExtensions {
		supportedMap[ext] = true
	}

	for _, ext := range extensions {
		if supportedMap[ext] {
			valid = append(valid, ext)
		} else {
			invalid = append(invalid, ext)
		}
	}

	return valid, invalid
}

// GetSieveCapabilities returns the SIEVE capabilities that should be
// advertised to clients: exactly the configured supported-extensions list.
//
// Only advertise what the host actually validates against, because a script
// using an advertised-but-unvalidatable extension would be rejected on upload.
func GetSieveCapabilities(supportedExtensions []string) []string {
	// Return a copy to prevent external modification
	capabilities := make([]string, len(supportedExtensions))
	copy(capabilities, supportedExtensions)
	return capabilities
}
