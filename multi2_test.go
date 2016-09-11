package multi2

import (
	"bytes"
	"encoding/hex"
	"testing"
)

var tests = []struct {
	key    string
	plain  string
	cipher string
}{
	{"00000000000000000000000000000000000000000000000000000000000000000123456789ABCDEF", "0000000000000001", "F89440845E11CF89"},
	{"00000000000000000000000000000000000000000000000000000000000000000123456789ABCDEF", "0000000000000002", "6EFA3A6FA860F2A6"},
}

func BenchmarkMulti2(b *testing.B) {
	for i := 0; i < b.N; i++ {

	}
}
func TestMulti2(t *testing.T) {
	for _, group := range tests {
		var key, pt, ct, dst []byte
		key, _ = hex.DecodeString(group.key)
		pt, _ = hex.DecodeString(group.plain)
		ct, _ = hex.DecodeString(group.cipher)

		cipher, _ := NewCipher(key)
		dst = make([]byte, len(ct))
		cipher.Encrypt(dst, pt)
		if !bytes.Equal(dst, ct) {
			t.Errorf("encrypt failed:\ngot : % 02X\nwant: % 02X", dst, ct)
		}

		dst = make([]byte, len(pt))
		cipher.Decrypt(dst, ct)

		if !bytes.Equal(dst, pt) {
			t.Errorf("decrypt failed:\ngot : % 02X\nwant: % 02X", dst, pt)
		}
	}
}
