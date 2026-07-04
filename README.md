# go-managesieve

A dependency-free ManageSieve (RFC 5804) server library for Go, with a
matching minimal client for proxy front-ends. You implement a single `Session`
interface for storage, authentication, and Sieve validation; the library
handles the wire protocol, the RFC 5804 state machine, quoted strings and
`{N}`/`{N+}` literals, SASL PLAIN framing, STARTTLS, timeouts, and abuse
limits.

- Zero dependencies beyond the standard library.
- Validation-agnostic — the library never parses Sieve; `PutScript`,
  `CheckScript` and `SetActive` validate host-side (e.g. with
  [go-sieve](https://github.com/migadu/go-sieve)), so capability
  advertisement and validation can never drift apart.
- Hardened defaults — idle/absolute/write timeouts, line-length caps, a
  per-connection error limit with progressive back-off, panic isolation,
  oversized literals rejected *before* their content is read, and
  response-splitting-safe encoding.
- Proxy-friendly — `Conn.Hijack()` and the `managesieveclient` package let a
  session authenticate upstream and relay raw bytes.

## Install

```sh
go get github.com/migadu/go-managesieve
```

Requires Go 1.25 or newer.

## Packages

| Package | Purpose |
| --- | --- |
| [`managesieve`](./managesieve) | Shared wire types and helpers (`ScriptInfo`, `Capability`, `Quote`, `ValidateScriptName`, SIEVE extension lists). |
| [`managesieveserver`](./managesieveserver) | The server: `Server`, `Options`, the `Session` interface, `Conn`, `Error`. |
| [`managesieveclient`](./managesieveclient) | Minimal client for proxy front-ends. |
| [`managesievemem`](./managesievemem) | Concurrency-safe in-memory script store implementing `Session`; for tests and local dev. |

## Quick start

```go
package main

import (
	"log"

	"github.com/migadu/go-managesieve/managesieve"
	"github.com/migadu/go-managesieve/managesievemem"
	"github.com/migadu/go-managesieve/managesieveserver"
)

func main() {
	store := managesievemem.New()
	store.AddUser("alice@example.com", "s3cret")

	srv := managesieveserver.New(managesieveserver.Options{
		NewSession:      store.NewSession,
		Greeting:        `"example.com" ManageSieve server ready.`,
		SieveExtensions: managesieve.DefaultEnabledExtensions,
		MaxScriptSize:   64 * 1024,
		InsecureAuth:    true, // allow auth without TLS — development only
	})

	log.Fatal(srv.ListenAndServe(":4190"))
}
```

## Response codes and byte-level control

Session methods signal failures with `*managesieveserver.Error`:

```go
return &managesieveserver.Error{Code: "NONEXISTENT", Message: "Script does not exist"}
// wire: NO (NONEXISTENT) "Script does not exist"

return &managesieveserver.Error{Message: "Authentication failed", Close: true}
// wire: NO Authentication failed   (then the connection is closed)
```

An uncoded `Error` message is emitted verbatim after `NO `, so an embedder
that wants RFC quoted-string framing pre-quotes with `managesieve.Quote` —
this gives hosts byte-exact control over their responses. With
`Options.StrictSessionErrors` set, plain (non-`*Error`) errors are masked as
`NO "internal error"` so backend error strings can never leak to clients.

## Proxying

A proxy implements `Session.AuthenticatePlain` to authenticate the downstream
client, dials the backend (optionally with the `managesieveclient` package),
then calls `Conn.Hijack()` to take over the raw socket and relay bytes. Bytes
the client pipelined behind the authentication exchange are preserved in the
hijacked `*bufio.Reader`.

## License

MIT — see [LICENSE](./LICENSE). © Migadu-Mail GmbH.
