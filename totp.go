package totp

// 30 seconds.
const DEFAULT_STEP uint64 = 30

// 8 digits of output.
const DEFAULT_DIGITS uint32 = 8

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
