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
	Rand            io.Reader
	gx              *big.Int
	gy              *big.Int
	protocolVersion [2]byte
	sendInstag      uint32
	receiveInstag   uint32
}

const (
	msgTypeDHCommit = 2
	msgTypeDHKey    = 10
)

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

func (ake *AKE) generateRand() (*big.Int, error) {
	var randx [40]byte
	_, err := io.ReadFull(ake.rand(), randx[:])
	if err != nil {
		return nil, err
	}
	return new(big.Int).SetBytes(randx[:]), nil
}

func (ake *AKE) initGx() error {
	x, err := ake.generateRand()
	if err != nil {
		return err
	}

	gx := new(big.Int).Exp(g, x, p)
	ake.gx = gx

	return nil
}

func (ake *AKE) initGy() error {
	y, err := ake.generateRand()
	if err != nil {
		return err
	}

	gy := new(big.Int).Exp(g, y, p)
	ake.gy = gy

	return nil
}

func (ake *AKE) encryptedGx() ([]byte, error) {
	var randr [16]byte

	_, err := io.ReadFull(ake.rand(), randr[:])
	if err != nil {
		return nil, err
	}

	aesCipher, err := aes.NewCipher(randr[:])
	if err != nil {
		return nil, err
	}

	var gxMPI = appendMPI([]byte{}, ake.gx)
	ciphertext := make([]byte, len(gxMPI))
	iv := ciphertext[:aes.BlockSize]
	stream := cipher.NewCTR(aesCipher, iv)
	stream.XORKeyStream(ciphertext, gxMPI)

	return ciphertext, nil
}

func (ake *AKE) hashedGx() []byte {
	out := sha256.Sum256(ake.gx.Bytes())
	return out[:]
}

func (ake *AKE) DHCommitMessage() ([]byte, error) {
	var out []byte

	err := ake.initGx()
	if err != nil {
		return nil, err
	}

	encryptedGx, err := ake.encryptedGx()
	if err != nil {
		return nil, err
	}

	out = appendBytes(out, ake.protocolVersion[:])
	out = append(out, msgTypeDHCommit)
	out = appendWord(out, ake.sendInstag)
	out = appendWord(out, ake.receiveInstag)
	out = appendBytes(out, encryptedGx)
	out = appendBytes(out, ake.hashedGx())

	return out, nil
}

func (ake *AKE) DHKeyMessage() []byte {
	var out []byte
	ake.initGy()
	out = appendBytes(out, ake.protocolVersion[:])
	out = append(out, msgTypeDHKey)
	out = appendWord(out, ake.sendInstag)
	out = appendWord(out, ake.receiveInstag)
	out = appendMPI(out, ake.gy)

	return out
}
