package otr3

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"io"
	"math/big"
)

type AKE struct {
	Rand io.Reader
	gx   big.Int
}

var (
	g *big.Int // group generator
)

func init() {
	g = new(big.Int).SetInt64(2)
}

func (ake *AKE) rand() io.Reader {
	if ake.Rand != nil {
		return ake.Rand
	}
	return rand.Reader
}

func (ake *AKE) initGx() {
	var randx [40]byte
	_, err := io.ReadFull(ake.rand(), randx[:])
	if err != nil {
		panic(err)
	}
	x := new(big.Int).SetBytes(randx[:])
	gx := new(big.Int).Exp(g, x, p)
	ake.gx = *gx
}

func (ake *AKE) encryptGx() []byte {
	var randr [16]byte
	_, err := io.ReadFull(ake.rand(), randr[:])

	aesCipher, err := aes.NewCipher(randr[:])
	if err != nil {
		panic(err)
	}
	ciphertext := make([]byte, len(BytesToMPI(ake.gx.Bytes())))
	iv := ciphertext[:aes.BlockSize]
	stream := cipher.NewCTR(aesCipher, iv)
	stream.XORKeyStream(ciphertext, BytesToMPI(ake.gx.Bytes()))
	return ciphertext
}

func (ake *AKE) hashedGx() [32]byte {
	return sha256.Sum256(ake.gx.Bytes())
}

func BytesToMPI(v []byte) []byte {
	var out []byte
	length := Uint32toBytes(uint32(len(v)))
	out = append(out, length[:]...)
	out = append(out, v...)
	return out
}

func Uint32toBytes(i uint32) [4]byte {
	return [4]byte{byte(i >> 24), byte(i >> 16), byte(i >> 8), byte(i)}
}
