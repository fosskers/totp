package totp

import (
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"hash"
	"testing"
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

// --- Documentation Examples --- //

// TODO
func ExampleTotp() {
	fmt.Println("foobar")
}