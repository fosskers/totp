[![Workflow Status](https://github.com/fosskers/totp/workflows/Go/badge.svg)](https://github.com/fosskers/totp/actions?query=workflow%3A%22Go%22)
[![Go Report Card](https://goreportcard.com/badge/github.com/fosskers/totp)](https://goreportcard.com/report/github.com/fosskers/totp)
[![PkgGoDev](https://pkg.go.dev/badge/github.com/fosskers/totp)](https://pkg.go.dev/github.com/fosskers/totp)

# totp

A simple, correct TOTP library.

Time-based One-time Passwords are a useful way to authenticate a client,
since a valid password expires long before it could ever be guessed by an
attacker. This library provides an implementation of TOTP that matches its
specification [RFC6238], along with a simple interface.

## Usage

The `Totp` function is likely what you need. It uses the default time step
of 30 seconds and produces 8 digits of output:

```go
 // Negotiated between you and the authenticating service.
 password := []byte("secret")

 // The number of seconds since the Unix Epoch.
 seconds := uint64(time.Now().Unix())

 // Specify the desired Hash algorithm from the Standard Library.
 // For TOTP, sha1 and sha256 are also valid.
 totp := Totp(sha512.New, password, seconds)
```

For full control over how the algorithm is configured, consider
`TotpCustom`.

## Resources
- [RFC6238: TOTP][RFC6238]
- [RFC6238 Errata](https://www.rfc-editor.org/errata_search.php?rfc=6238)

[RFC6238]: https://tools.ietf.org/html/rfc6238

License: MIT
