package otr3

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
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

func (ake *AKE) generateEncryptedSignature() []byte {

	//Mb
	publicKey, _ := hex.DecodeString("000000000080a5138eb3d3eb9c1d85716faecadb718f87d31aaed1157671d7fee7e488f95e8e0ba60ad449ec732710a7dec5190f7182af2e2f98312d98497221dff160fd68033dd4f3a33b7c078d0d9f66e26847e76ca7447d4bab35486045090572863d9e4454777f24d6706f63e02548dfec2d0a620af37bbc1d24f884708a212c343b480d00000014e9c58f0ea21a5e4dfd9f44b6a9f7f6a9961a8fa9000000803c4d111aebd62d3c50c2889d420a32cdf1e98b70affcc1fcf44d59cca2eb019f6b774ef88153fb9b9615441a5fe25ea2d11b74ce922ca0232bd81b3c0fcac2a95b20cb6e6c0c5c1ace2e26f65dc43c751af0edbb10d669890e8ab6beea91410b8b2187af1a8347627a06ecea7e0f772c28aae9461301e83884860c9b656c722f0000008065af8625a555ea0e008cd04743671a3cda21162e83af045725db2eb2bb52712708dc0cc1a84c08b3649b88a966974bde27d8612c2861792ec9f08786a246fcadd6d8d3a81a32287745f309238f47618c2bd7612cb8b02d940571e0f30b96420bcd462ff542901b46109b1e5ad6423744448d20a57818a8cbb1647d0fea3b664e")
	var verifyData []byte
	verifyData = appendMPI(verifyData, ake.gx)
	verifyData = appendMPI(verifyData, ake.gy)
	verifyData = append(verifyData, publicKey...)
	verifyData = appendWord(verifyData, ake.myKeyId)
	mac := hmac.New(sha256.New, ake.revealKey.m1[:])
	mac.Write(verifyData)
	//TODO mb is used in Key sign() mb := mac.Sum(nil)

	//Xb
	var xb []byte
	xb = appendWord(publicKey, ake.myKeyId)
	sigb, _ := hex.DecodeString("86e8158880882a85ca444ce5c31641ff321864ce0a23707826c7f5181638512ca79ebeb319986f4b")

	xb = append(xb, sigb...)
	aesCipher, err := aes.NewCipher(ake.revealKey.c[:])
	if err != nil {
		panic(err.Error())
	}

	var iv [aes.BlockSize]byte
	ctr := cipher.NewCTR(aesCipher, iv[:])
	ctr.XORKeyStream(xb, xb)

	return appendBytes(nil, xb)
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
	out = appendBytes(out, ake.generateEncryptedSignature())
	//	out = appendBytes(out, ake.macSig())
	return out
}
