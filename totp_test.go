package totp

import (
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"hash"
	"testing"
	"time"
)

// --- Unit Tests --- //

func testBytes(t *testing.T, expected [8]byte, result [8]byte) {
	if result != expected {
		t.Errorf("toBytes: expected ?, got ?") // TODO How to print byte arrays?
	}
}

func TestToBytes(t *testing.T) {
	testBytes(t, [8]byte{0, 0, 0, 0, 0, 0, 0, 1}, toBytes(59/DEFAULT_STEP))
	testBytes(t, [8]byte{0, 0, 0, 0, 0x02, 0x35, 0x23, 0xec}, toBytes(1111111109/DEFAULT_STEP))
	testBytes(t, [8]byte{0, 0, 0, 0, 0x27, 0xbc, 0x86, 0xaa}, toBytes(20000000000/DEFAULT_STEP))
}

func testTotp(t *testing.T, h func() hash.Hash, secret []byte, time uint64, expected string) {
	hash := Totp(h, secret, time)
	if hash != expected {
		t.Errorf("Totp: expected %s, got %s", expected, hash)
	}
}

func TestTotp1(t *testing.T) {
	secret := []byte("12345678901234567890")
	if len(secret) != 20 {
		t.Errorf("Byte Conversion: expected 20, got %d", len(secret))
	}

	testTotp(t, sha1.New, secret, 59, "94287082")
	testTotp(t, sha1.New, secret, 1111111109, "07081804")
	testTotp(t, sha1.New, secret, 1111111111, "14050471")
	testTotp(t, sha1.New, secret, 1234567890, "89005924")
	testTotp(t, sha1.New, secret, 2000000000, "69279037")
	testTotp(t, sha1.New, secret, 20000000000, "65353130")
}

func TestTotp256(t *testing.T) {
	secret := []byte("12345678901234567890123456789012")
	if len(secret) != 32 {
		t.Errorf("Byte Conversion: expected 32, got %d", len(secret))
	}

	testTotp(t, sha256.New, secret, 59, "46119246")
	testTotp(t, sha256.New, secret, 1111111109, "68084774")
	testTotp(t, sha256.New, secret, 1111111111, "67062674")
	testTotp(t, sha256.New, secret, 1234567890, "91819424")
	testTotp(t, sha256.New, secret, 2000000000, "90698825")
	testTotp(t, sha256.New, secret, 20000000000, "77737706")
}

func TestTotp512(t *testing.T) {
	secret := []byte("1234567890123456789012345678901234567890123456789012345678901234")
	if len(secret) != 64 {
		t.Errorf("Byte Conversion: expected 64, got %d", len(secret))
	}

	testTotp(t, sha512.New, secret, 59, "90693936")
	testTotp(t, sha512.New, secret, 1111111109, "25091201")
	testTotp(t, sha512.New, secret, 1111111111, "99943326")
	testTotp(t, sha512.New, secret, 1234567890, "93441116")
	testTotp(t, sha512.New, secret, 2000000000, "38618901")
	testTotp(t, sha512.New, secret, 20000000000, "47863826")
}

func TestVariableLength(t *testing.T) {
	secret := []byte("12345678901234567890123456789012")
	hash := TotpCustom(sha256.New, DEFAULT_STEP, 10, secret, 100)
	if hash != "2102975832" {
		t.Errorf("Expected 10 digits, got the hash: %s", hash)
	}

	hash = TotpCustom(sha256.New, DEFAULT_STEP, 6, secret, 100)
	if hash != "975832" {
		t.Errorf("Expected 6 digits, got the hash: %s", hash)
	}
}

// --- Documentation Examples --- //

func ExampleTotp() {
	password := []byte("secret")
	seconds := uint64(time.Now().Unix())
	totp := Totp(sha512.New, password, seconds)
	fmt.Println(totp)
}

// This example uses a step size of 15 seconds (i.e. the password would expire
// faster) and a digit count of 6. Consider DEFAULT_STEP and DEFAULT_DIGITS if
// you only need to alter one of the arguments.
func ExampleTotpCustom() {
	password := []byte("secret")
	seconds := uint64(time.Now().Unix())
	totp := TotpCustom(sha512.New, 15, 6, password, seconds)
	fmt.Println(totp)
}
