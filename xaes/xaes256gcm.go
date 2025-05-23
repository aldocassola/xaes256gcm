package xaes256gcm

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/subtle"
	"fmt"
)

const (
	nonceSize int = 24
	keysize   int = 32
	overhead      = 16
)

type xaesGcm struct {
	c  cipher.Block
	k1 []byte
}

func New(key []byte) (cipher.AEAD, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("invalid key length")
	}

	l := make([]byte, aes.BlockSize)
	c, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	c.Encrypt(l[:aes.BlockSize], l[:aes.BlockSize])

	res := &xaesGcm{
		c:  c,
		k1: newK1(l),
	}
	return res, nil
}

func (x *xaesGcm) Overhead() int {
	return overhead
}

func (x *xaesGcm) NonceSize() int {
	return nonceSize
}

func newK1(l []byte) []byte {
	var msb byte
	for i := len(l) - 1; i >= 0; i-- {
		l[i], msb = (l[i]<<1)|msb, l[i]>>7
	}

	l[len(l)-1] = l[len(l)-1] ^ msb*0b10000111

	return l
}

func (x *xaesGcm) rekey(nonce []byte) []byte {
	kx := make([]byte, 0, aes.BlockSize*2)
	kx = append(kx, byte(0), byte(1), byte(0x58), byte(0))
	kx = append(kx, nonce[:12]...)
	kx = append(kx, byte(0), byte(2), byte(0x58), byte(0))
	kx = append(kx, nonce[:12]...)
	subtle.XORBytes(kx[:aes.BlockSize], kx[:aes.BlockSize], x.k1)
	subtle.XORBytes(kx[aes.BlockSize:], kx[aes.BlockSize:], x.k1)
	x.c.Encrypt(kx[:aes.BlockSize], kx[:aes.BlockSize])
	x.c.Encrypt(kx[aes.BlockSize:], kx[aes.BlockSize:])

	return kx
}

func (x *xaesGcm) Seal(dst, nonce, plaintext, additional []byte) []byte {
	if len(nonce) != nonceSize {
		panic("invalid nonce length")
	}

	k, n := x.rekey(nonce), nonce[12:]
	c, _ := aes.NewCipher(k)
	gcm, _ := cipher.NewGCM(c)

	return gcm.Seal(dst, n, plaintext, additional)
}

func (x *xaesGcm) Open(dst, nonce, ciphertext, additional []byte) ([]byte, error) {
	if len(nonce) != nonceSize {
		return nil, fmt.Errorf("invalide nonce length")
	}

	k, n := x.rekey(nonce), nonce[12:]
	c, _ := aes.NewCipher(k)
	gcm, _ := cipher.NewGCM(c)

	return gcm.Open(dst, n, ciphertext, additional)
}
