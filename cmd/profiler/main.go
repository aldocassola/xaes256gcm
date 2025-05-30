package main

import (
	"bytes"
	"crypto/rand"
	"log"
	"os"
	"runtime/pprof"

	xaes256gcm "github.com/aldocassola/xaes256gcm/xaes"
)

func foo() {
	key := make([]byte, xaes256gcm.Keysize)
	nonce := make([]byte, xaes256gcm.NonceSize)
	ptBuf := make([]byte, 4096)
	aadBuf := make([]byte, 256)
	decryptBuf := make([]byte, 4096+xaes256gcm.Overhead)
	ctBuf := make([]byte, 4096+xaes256gcm.Overhead)
	rand.Read(key)
	rand.Read(nonce)

	x, err := xaes256gcm.New(key)
	if err != nil {
		log.Fatal(err)
	}

	rand.Read(ptBuf)
	rand.Read(aadBuf)
	ct := x.Seal(ctBuf[:0], nonce, ptBuf, aadBuf)
	dec, err := x.Open(decryptBuf[:0], nonce, ct, aadBuf)
	if err != nil {
		log.Print("failed to decrypt:", err)
	}

	if !bytes.Equal(ptBuf, dec) {
		log.Printf("invalid decryption:%v", dec)
	}

}

func main() {
	out, err := os.Create("cpu.pprof")
	if err != nil {
		log.Fatal(err)
	}

	err = pprof.StartCPUProfile(out)
	if err != nil {
		log.Fatal(err)
	}

	defer out.Close()
	defer pprof.StopCPUProfile()

	for range 100_000 {
		foo()
	}
}
