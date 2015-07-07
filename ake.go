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
	gx   *big.Int
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
	ake.gx = gx
}

func (ake *AKE) encryptGx() []byte {
	var randr [16]byte
	_, err := io.ReadFull(ake.rand(), randr[:])

	aesCipher, err := aes.NewCipher(randr[:])
	if err != nil {
		panic(err)
	}
	var gxMPI = appendMPI([]byte{}, ake.gx)
	ciphertext := make([]byte, len(gxMPI))
	iv := ciphertext[:aes.BlockSize]
	stream := cipher.NewCTR(aesCipher, iv)
	stream.XORKeyStream(ciphertext, gxMPI)
	return ciphertext
}

func (ake *AKE) hashedGx() [32]byte {
	return sha256.Sum256(ake.gx.Bytes())
}
