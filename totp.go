// A simple, correct TOTP implementation.
//
// Time-based One-time Passwords are a useful way to authenticate a client,
// since a valid password expires long before it could ever be guessed by an
// attacker. This library provides an implementation of TOTP that matches its
// specification (RFC6238), along with a simple interface.
//
// Usage
//
// The Totp function is likely what you need. It uses the default time step of
// 30 seconds and gives 8 digits of output:
//
//   // Negotiated between you and the authenticating service.
//   password := []byte("secret")
//
//   // The number of seconds since the Unix Epoch.
//   seconds := uint64(time.Now().Unix())
//
//   // Specify the desired Hash algorithm from the Standard Library.
//   // For TOTP, sha1 and sha256 are also valid.
//   totp := Totp(sha512.New, password, seconds)
//
// Resources
//
// See RFC6239 (https://tools.ietf.org/html/rfc6238) and its Errata
// (https://www.rfc-editor.org/errata_search.php?rfc=6238) for more information.
package totp

import (
	"crypto/hmac"
	"fmt"
	"hash"
)

// DEFAULT_STEP represents a 30 second time step.
const DEFAULT_STEP uint64 = 30

// DEFAULT_DIGITS represents 8 digits of final output.
const DEFAULT_DIGITS uint32 = 8

// Totp produces a Time-based One-time Password with default settings.
func Totp(h func() hash.Hash, password []byte, time uint64) string {
	return TotpCustom(h, DEFAULT_STEP, DEFAULT_DIGITS, password, time)
}

// TotpCustom produces a Time-based One-time Password with full control over
// algorithm parameters.
func TotpCustom(h func() hash.Hash, step uint64, digits uint32, password []byte, time uint64) string {
	// Hash the secret and the time together.
	mac := hmac.New(h, password)
	bytes := toBytes(time / step)
	mac.Write(bytes[:])
	hash := mac.Sum(nil)

	// Magic from the RFC that produces our final value.
	offset := hash[len(hash)-1] & 0xf
	binary := (uint64(hash[offset]&0x7f) << 24) | (uint64(hash[offset+1]) << 16) | (uint64(hash[offset+2]) << 8) | uint64(hash[offset+3])

	return fmt.Sprintf("%0[2]*[1]d", binary%intPow10(uint64(digits)), digits)
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

// intPow10 is similar to `Pow`, but operates strictly with integers.
func intPow10(power uint64) uint64 {
	if power == 0 {
		return 1
	}

	var result uint64 = 10
	for i := power; i > 1; i-- {
		result *= 10
	}
	return result
}
