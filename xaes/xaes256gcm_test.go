package xaes256gcm

import (
	"bytes"
	"crypto/aes"
	"encoding/hex"
	"testing"

	"golang.org/x/crypto/sha3"
)

func unhex(v string) []byte {
	ret, _ := hex.DecodeString(v)
	return ret
}

func TestBasic(t *testing.T) {
	tests := []struct {
		K                       []byte
		N                       string
		L, K1, M1, M2, K_x, N_x []byte
		Plaintext, AAD          string
		Ciphertext              []byte
	}{
		/*
			K: 0101010101010101010101010101010101010101010101010101010101010101
			N: "ABCDEFGHIJKLMNOPQRSTUVWX"

			L: 7298caa565031eadc6ce23d23ea66378
			K1: e531954aca063d5b8d9c47a47d4cc6f0
			M1: 000158004142434445464748494a4b4c
			M2: 000258004142434445464748494a4b4c
			Kₓ: c8612c9ed53fe43e8e005b828a1631a0bbcb6ab2f46514ec4f439fcfd0fa969b
			Nₓ: 4d4e4f505152535455565758

			Plaintext: "XAES-256-GCM"
			AAD: ""
			Ciphertext: ce546ef63c9cc60765923609b33a9a1974e96e52daf2fcf7075e2271
		*/
		{
			K:          unhex("0101010101010101010101010101010101010101010101010101010101010101"),
			N:          "ABCDEFGHIJKLMNOPQRSTUVWX",
			L:          unhex("7298caa565031eadc6ce23d23ea66378"),
			K1:         unhex("e531954aca063d5b8d9c47a47d4cc6f0"),
			M1:         unhex("000158004142434445464748494a4b4c"),
			M2:         unhex("000258004142434445464748494a4b4c"),
			K_x:        unhex("c8612c9ed53fe43e8e005b828a1631a0bbcb6ab2f46514ec4f439fcfd0fa969b"),
			N_x:        unhex("4d4e4f505152535455565758"),
			Plaintext:  "XAES-256-GCM",
			AAD:        "",
			Ciphertext: unhex("ce546ef63c9cc60765923609b33a9a1974e96e52daf2fcf7075e2271"),
		},
		/*
			K: 0303030303030303030303030303030303030303030303030303030303030303
			N: "ABCDEFGHIJKLMNOPQRSTUVWX"

			L: 91c08762876dccf9ba204a33768fa5fe
			K1: 23810ec50edb99f374409466ed1f4b7b
			M1: 000158004142434445464748494a4b4c
			M2: 000258004142434445464748494a4b4c
			Kₓ: e9c621d4cdd9b11b00a6427ad7e559aeedd66b3857646677748f8ca796cb3fd8
			Nₓ: 4d4e4f505152535455565758

			Plaintext: "XAES-256-GCM"
			AAD: "c2sp.org/XAES-256-GCM"
			Ciphertext: 986ec1832593df5443a179437fd083bf3fdb41abd740a21f71eb769d,
		*/
		{
			K:          unhex("0303030303030303030303030303030303030303030303030303030303030303"),
			N:          "ABCDEFGHIJKLMNOPQRSTUVWX",
			L:          unhex("91c08762876dccf9ba204a33768fa5fe"),
			K1:         unhex("23810ec50edb99f374409466ed1f4b7b"),
			M1:         unhex("000158004142434445464748494a4b4c"),
			M2:         unhex("000258004142434445464748494a4b4c"),
			K_x:        unhex("e9c621d4cdd9b11b00a6427ad7e559aeedd66b3857646677748f8ca796cb3fd8"),
			N_x:        unhex("4d4e4f505152535455565758"),
			Plaintext:  "XAES-256-GCM",
			AAD:        "c2sp.org/XAES-256-GCM",
			Ciphertext: unhex("986ec1832593df5443a179437fd083bf3fdb41abd740a21f71eb769d"),
		},
	}

	for _, tv := range tests {

		c, _ := aes.NewCipher(tv.K)
		l := newL(c)
		if !bytes.Equal(l, tv.L) {
			t.Error("L mismatch", l)
		}

		x, _ := New(tv.K)
		xaes := x.(*xaesGcm)
		k1 := xaes.k1
		if !bytes.Equal(k1, tv.K1) {
			t.Error("K1 mismatch:", k1)
		}

		ms := newMs([]byte(tv.N))
		m1 := ms[:aes.BlockSize]
		m2 := ms[aes.BlockSize:]
		if !bytes.Equal(m1, tv.M1) {
			t.Error("M1 mismatch:", m1)
		}

		if !bytes.Equal(m2, tv.M2) {
			t.Error("M2 mismatch:", m2)
		}

		kx := xaes.rekey([]byte(tv.N))
		if !bytes.Equal(kx, tv.K_x) {
			t.Error("K_x mismatch:", kx)
		}

		if !bytes.Equal([]byte(tv.N)[12:], tv.N_x) {
			t.Error("N_x mismatch:", tv.N_x)
		}

		ct := x.Seal([]byte{}, []byte(tv.N), []byte(tv.Plaintext), []byte(tv.AAD))
		if !bytes.Equal(tv.Ciphertext, ct) {
			t.Errorf("ciphertext mismatch:%v", ct)
		}
	}
}

func Test_Cumulative(t *testing.T) {
	First := unhex("7f9c2ba4e88f827d616045507605853e")
	Hash10K := unhex("e6b9edf2df6cec60c8cbd864e2211b597fb69a529160cd040d56c0c210081939")
	Hash1M := unhex("2163ae1445985a30b60585ee67daa55674df06901b890593e824b8a7c885ab15")
	rand := sha3.NewShake128()
	shake := sha3.NewShake128()

	first := make([]byte, 16)
	rand.Read(first)
	if !bytes.Equal(first, First) {
		t.Errorf("SHAKE128 first mismatch: %x", first)
	}

	rand.Reset()
	for i := range 1_000_000 {
		k := make([]byte, Keysize)
		rand.Read(k)
		n := make([]byte, NonceSize)
		rand.Read(n)
		lenbyte := make([]byte, 1)
		rand.Read(lenbyte)
		pt := make([]byte, int(lenbyte[0]))
		rand.Read(pt)
		rand.Read(lenbyte)
		aad := make([]byte, int(lenbyte[0]))
		rand.Read(aad)

		x, _ := New(k)
		ct := x.Seal(nil, n, pt, aad)
		shake.Write(ct)
		hashed := shake.Sum(nil)

		if i == 10_000-1 && !bytes.Equal(hashed, Hash10K) {
			t.Errorf("10K hash mismatch:%x", hashed)
		}

		if !testing.Short() && i == 1_000_000-1 && !bytes.Equal(hashed, Hash1M) {
			t.Errorf("1M hash mismatch:%x", hashed)
		}
	}

}
