package otr3

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/dsa"
	"crypto/rand"
	"crypto/sha256"
	"hash"
	"io"
	"math/big"
)

type AKE struct {
	PrivateKey          *PrivateKey
	Rand                io.Reader
	r                   [16]byte
	x, y                *big.Int
	gx, gy              *big.Int
	protocolVersion     [2]byte
	senderInstanceTag   uint32
	receiverInstanceTag uint32
	revealKey, sigKey   akeKeys
	ssid                [8]byte
	myKeyId             uint32
}

type akeKeys struct {
	c      [16]byte
	m1, m2 [32]byte
}

type PrivateKey struct {
	PublicKey
	dsa.PrivateKey
}

type PublicKey struct {
	dsa.PublicKey
}

const (
	msgTypeDHCommit = 2
	msgTypeDHKey    = 10
	msgTypeRevelSig = 17
)

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

func (ake *AKE) encryptedGx() ([]byte, error) {
	_, err := io.ReadFull(ake.rand(), ake.r[:])

	aesCipher, err := aes.NewCipher(ake.r[:])
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

func (ake *AKE) calcAKEKeys() {
	s := ake.calcDHSharedSecret()
	secbytes := appendMPI(nil, s)
	h := sha256.New()
	copy(ake.ssid[:], h2(0x00, secbytes, h)[:8])
	copy(ake.revealKey.c[:], h2(0x01, secbytes, h)[:16])
	copy(ake.sigKey.c[:], h2(0x01, secbytes, h)[16:])
	copy(ake.revealKey.m1[:], h2(0x02, secbytes, h))
	copy(ake.revealKey.m2[:], h2(0x03, secbytes, h))
	copy(ake.sigKey.m1[:], h2(0x04, secbytes, h))
	copy(ake.sigKey.m2[:], h2(0x05, secbytes, h))
}

func h2(b byte, secbytes []byte, h hash.Hash) []byte {
	h.Reset()
	var p [1]byte
	p[0] = b
	h.Write(p[:])
	h.Write(secbytes[:])
	out := h.Sum(nil)
	return out[:]
}

func (ake *AKE) calcDHSharedSecret() *big.Int {
	return new(big.Int).Exp(ake.gy, ake.x, p)
}

func (ake *AKE) DHCommitMessage() ([]byte, error) {
	var out []byte
	ake.myKeyId = 0

	x, err := ake.generateRand()
	if err != nil {
		return nil, err
	}

	ake.x = x
	ake.gx = new(big.Int).Exp(g1, ake.x, p)
	encryptedGx, err := ake.encryptedGx()
	if err != nil {
		return nil, err
	}

	out = appendBytes(out, ake.protocolVersion[:])
	out = append(out, msgTypeDHCommit)
	out = appendWord(out, ake.senderInstanceTag)
	out = appendWord(out, ake.receiverInstanceTag)
	out = appendBytes(out, encryptedGx)
	out = appendBytes(out, ake.hashedGx())

	return out, nil
}

func (ake *AKE) DHKeyMessage() ([]byte, error) {
	var out []byte
	y, err := ake.generateRand()

	if err != nil {
		return nil, err
	}
	ake.y = y
	ake.gy = new(big.Int).Exp(g1, ake.y, p)
	out = appendBytes(out, ake.protocolVersion[:])
	out = append(out, msgTypeDHKey)
	out = appendWord(out, ake.senderInstanceTag)
	out = appendWord(out, ake.receiverInstanceTag)
	out = appendMPI(out, ake.gy)

	return out, nil
}

func (ake *AKE) RevealSigMessage() []byte {
	var out []byte
	out = appendBytes(out, ake.protocolVersion[:])
	out = append(out, msgTypeRevelSig)
	out = appendWord(out, ake.senderInstanceTag)
	out = appendWord(out, ake.receiverInstanceTag)
	out = appendBytes(out, ake.r[:])
	//	out = appendBytes(out, ake.encryptedSig())
	//	out = appendBytes(out, ake.macSig())
	return out
}
