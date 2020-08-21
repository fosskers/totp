package totp

import (
	"fmt"
	"testing"
)

func TestToBytes(t *testing.T) {
	expected := [8]byte{0, 0, 0, 0, 0, 0, 0, 1}
	result := toBytes(59 / DEFAULT_STEP)
	if result != expected {
		t.Errorf("toBytes: expected ?, got ?")
	}

	expected = [8]byte{0, 0, 0, 0, 0x02, 0x35, 0x23, 0xec}
	result = toBytes(1111111109 / DEFAULT_STEP)
	if result != expected {
		t.Errorf("toBytes: expected ?, got ?")
	}

	expected = [8]byte{0, 0, 0, 0, 0x27, 0xbc, 0x86, 0xaa}
	result = toBytes(20000000000 / DEFAULT_STEP)
	if result != expected {
		t.Errorf("toBytes: expected ?, got ?")
	}
}

// TODO
func ExampleTotp() {
	fmt.Println("foobar")
}
