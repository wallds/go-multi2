// Package multi2 implements the multi2 cipher
package multi2

/*
For more information, please see:
    https://en.wikipedia.org/wiki/MULTI2
*/

import (
	"crypto/cipher"
	"encoding/binary"
	"strconv"
)

const (
	BlockSize = 8
	KeySize   = 40
)

type multi2 struct {
	N  int
	uk [8]uint32
}

type KeySizeError int

func (k KeySizeError) Error() string { return "multi2: invalid key size " + strconv.Itoa(int(k)) }

// NewCipher returns a cipher.Block implementing multi2.  The key argument must be 16 bytes.
func NewCipher(key []byte) (cipher.Block, error) {
	c, err := NewCipherWithRounds(key, 128)
	return c, err
}

// NewCipherWithRounds --
func NewCipherWithRounds(key []byte, round int) (cipher.Block, error) {
	keylen := len(key)
	if keylen != KeySize {
		return nil, KeySizeError(keylen)
	}
	if round == 0 {
		round = 128
	}
	var sk [8]uint32
	var dk [2]uint32
	c := &multi2{}
	e := binary.BigEndian
	c.N = round
	for i := 0; i < 8; i++ {
		sk[i] = e.Uint32(key[i*4:])
	}
	dk[0] = e.Uint32(key[8*4:])
	dk[1] = e.Uint32(key[9*4:])

	var p [2]uint32
	p[0] = dk[0]
	p[1] = dk[1]
	t := 4
	n := 0
	_PI1(p[:])
	_PI2(p[:], sk[:])
	c.uk[n] = p[0]
	n++

	_PI3(p[:], sk[:])
	c.uk[n] = p[1]
	n++
	_PI4(p[:], sk[:])
	c.uk[n] = p[0]
	n++

	_PI1(p[:])
	c.uk[n] = p[1]
	n++

	_PI2(p[:], sk[t:])
	c.uk[n] = p[0]
	n++

	_PI3(p[:], sk[t:])
	c.uk[n] = p[1]
	n++

	_PI4(p[:], sk[t:])
	c.uk[n] = p[0]
	n++

	_PI1(p[:])
	c.uk[n] = p[1]
	n++
	return c, nil
}

func (c *multi2) BlockSize() int { return BlockSize }
func encrypt(p []uint32, N int, uk []uint32) {
	var n, t int
	for {
		_PI1(p)
		if n++; n == N {
			break
		}
		_PI2(p, uk[t:])
		if n++; n == N {
			break
		}
		_PI3(p, uk[t:])
		if n++; n == N {
			break
		}
		_PI4(p, uk[t:])
		if n++; n == N {
			break
		}
		t ^= 4
	}
}
func decrypt(p []uint32, N int, uk []uint32) {
	var n, t, x int
	t = 4 * ((N & 1) ^ 1)
	n = N
	for {
		if n >= 4 {
			x = 4
		} else {
			x = 0
		}
		if x >= 4 {
			_PI4(p, uk[t:])
			n--
			x--
		}
		if x >= 3 {
			_PI3(p, uk[t:])
			n--
			x--
		}
		if x >= 2 {
			_PI2(p, uk[t:])
			n--
			x--
		}
		if x >= 1 {
			_PI1(p)
			n--
		}
		if x == 0 {
			return
		}
		t ^= 4
	}
}
func (cipher *multi2) Encrypt(dst, src []byte) {
	e := binary.BigEndian
	var p [2]uint32
	p[0] = e.Uint32(src)
	p[1] = e.Uint32(src[4:])
	encrypt(p[:], cipher.N, cipher.uk[:])
	e.PutUint32(dst, p[0])
	e.PutUint32(dst[4:], p[1])
}

func (cipher *multi2) Decrypt(dst, src []byte) {
	e := binary.BigEndian
	var p [2]uint32
	p[0] = e.Uint32(src)
	p[1] = e.Uint32(src[4:])
	decrypt(p[:], cipher.N, cipher.uk[:])
	e.PutUint32(dst, p[0])
	e.PutUint32(dst[4:], p[1])
}
func _RORc(x, n uint32) uint32 {
	return (x >> (n & (32 - 1))) | (x << (32 - (n & (32 - 1))))
}
func _ROLc(x, n uint32) uint32 {
	return (x << (n & (32 - 1))) | (x >> (32 - (n & (32 - 1))))
}
func _ROR(x, n uint32) uint32 {
	return _RORc(x, n)
}
func _ROL(x, n uint32) uint32 {
	return _ROLc(x, n)
}
func _PI1(p []uint32) {
	p[1] ^= p[0]
}
func _PI2(p []uint32, k []uint32) {
	t := p[1] + k[0]
	t = _ROL(t, 1) + t - 1
	t = _ROL(t, 4) ^ t
	p[0] ^= t
}
func _PI3(p []uint32, k []uint32) {
	t := p[0] + k[1]
	t = _ROL(t, 2) + t + 1
	t = _ROL(t, 8) ^ t
	t = t + k[2]
	t = _ROL(t, 1) - t
	t = _ROL(t, 16) ^ (p[0] | t)
	p[1] ^= t
}
func _PI4(p []uint32, k []uint32) {
	t := p[1] + k[3]
	t = _ROL(t, 2) + t + 1
	p[0] ^= t
}
