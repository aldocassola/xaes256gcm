package xaes256gcm

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/subtle"
	"fmt"
)

const (
	NonceSize = 24
	Keysize   = 32
	Overhead  = 16
)

type xaesGcm struct {
	c  cipher.Block
	k1 []byte
}

func New(key []byte) (cipher.AEAD, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("invalid key length")
	}

	c, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	return &xaesGcm{
		c:  c,
		k1: newK1(newL(c)),
	}, nil
}

func (x *xaesGcm) Overhead() int {
	return Overhead
}

func (x *xaesGcm) NonceSize() int {
	return NonceSize
}

func newK1(l []byte) []byte {
	var msb byte
	for i := len(l) - 1; i >= 0; i-- {
		l[i], msb = (l[i]<<1)|msb, l[i]>>7
	}

	l[len(l)-1] = l[len(l)-1] ^ msb*0b10000111

	return l
}

func newL(c cipher.Block) []byte {
	zeros := make([]byte, aes.BlockSize)
	c.Encrypt(zeros[:], zeros[:])
	return zeros
}

func (x *xaesGcm) rekey(nonce []byte) []byte {
	kx := newMs(nonce)
	subtle.XORBytes(kx[:aes.BlockSize], kx[:aes.BlockSize], x.k1)
	subtle.XORBytes(kx[aes.BlockSize:], kx[aes.BlockSize:], x.k1)
	x.c.Encrypt(kx[:aes.BlockSize], kx[:aes.BlockSize])
	x.c.Encrypt(kx[aes.BlockSize:], kx[aes.BlockSize:])
	return kx
}

// return M1 and M2 concatenated
func newMs(nonce []byte) []byte {
	ms := make([]byte, 0, aes.BlockSize*2)
	ms = append(ms, 0, 1, 0x58, 0)
	ms = append(ms, nonce[:12]...)
	ms = append(ms, 0, 2, 0x58, 0)
	ms = append(ms, nonce[:12]...)
	return ms
}

func (x *xaesGcm) Seal(dst, nonce, plaintext, additional []byte) []byte {
	if len(nonce) != NonceSize {
		panic("invalid nonce length")
	}

	k, n := x.rekey(nonce), nonce[12:]
	c, _ := aes.NewCipher(k)
	gcm, _ := cipher.NewGCM(c)
	return gcm.Seal(dst, n, plaintext, additional)
}

func (x *xaesGcm) Open(dst, nonce, ciphertext, additional []byte) ([]byte, error) {
	if len(nonce) != NonceSize {
		return nil, fmt.Errorf("invalide nonce length")
	}

	k, n := x.rekey(nonce), nonce[12:]
	c, err := aes.NewCipher(k)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(c)
	if err != nil {
		return nil, err
	}

	return gcm.Open(dst, n, ciphertext, additional)
}
