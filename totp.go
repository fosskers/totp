// A simple, correct TOTP implementation.
//
// Time-based One-time Passwords are a useful way to authenticate a client,
// since a valid password expires long before it could ever be guessed by an
// attacker. This library provides an implementation of TOTP that matches its
// specification (RFC6238), along with a simple interface.
//
// Usage
//
// Here is an example:
//
//   Totp("whatever", 6)
//
// Resources
//
// See RFC6239 (https://tools.ietf.org/html/rfc6238) and its Errata
// (https://www.rfc-editor.org/errata_search.php?rfc=6238) for more information.
package totp

// DEFAULT_STEP represents a 30 second time step.
const DEFAULT_STEP uint64 = 30

// DEFAULT_DIGITS represents 8 digits of final output.
const DEFAULT_DIGITS uint32 = 8

// Totp is a cool function that orders you lunch. Yes
func Totp(password []byte, time uint64) string {
	return ""
}

// Convert an unsigned 64-bit int into its 8 individual bytes.
func toBytes(n uint64) [8]byte {
	const mask uint64 = 0x00000000000000ff
	bytes := [8]byte{0, 0, 0, 0, 0, 0, 0, 0}

	for i := range bytes {
		bytes[7-i] = byte(mask & (n >> (i * 8)))
	}

	return bytes
}
