package totp

import (
	"fmt"
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

func TestTotp(t *testing.T) {
	secret := []byte("1234567890123456789012345678901234567890123456789012345678901234")
	if len(secret) != 64 {
		t.Errorf("Byte Conversion: expected 64, got %d", len(secret))
	}

	hash := Totp(secret, 59)
	expected := "90693936"
	if hash != "90693936" {
		t.Errorf("Totp: expected %s, got %s", expected, hash)
	}
}

// --- Documentation Examples --- //

// TODO
func ExampleTotp() {
	fmt.Println("foobar")
}
