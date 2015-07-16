package otr3

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"hash"
	"io"
	"math/big"
)

// AKE is authenticated key exchange context
type AKE struct {
	akeContext
	ourKey            *PrivateKey
	r                 [16]byte
	revealKey, sigKey akeKeys
	ssid              [8]byte
	myKeyID           uint32
}

type akeKeys struct {
	c      [16]byte
	m1, m2 [32]byte
}

func (ake *AKE) rand() io.Reader {
	if ake.Rand != nil {
		return ake.Rand
	}
	return rand.Reader
}

func (ake *AKE) generateRandBytes(dst []byte) error {
	if _, err := io.ReadFull(ake.rand(), dst[:]); err != nil {
		return err
	}
	return nil
}

func (ake *AKE) generateRandBigInt() (*big.Int, error) {
	var randx [40]byte
	_, err := io.ReadFull(ake.rand(), randx[:])
	if err != nil {
		return nil, err
	}
	return new(big.Int).SetBytes(randx[:]), nil
}

func encrypt(r, src []byte) (dst []byte, err error) {
	aesCipher, err := aes.NewCipher(r)
	if err != nil {
		return nil, err
	}

	var gxMPI = appendMPI([]byte{}, new(big.Int).SetBytes(src))
	dst = make([]byte, len(gxMPI))
	iv := dst[:aes.BlockSize]
	stream := cipher.NewCTR(aesCipher, iv)
	stream.XORKeyStream(dst, gxMPI)

	return dst, nil
}

func decrypt(r, dst, src []byte) error {
	// aes decryption
	aesCipher, err := aes.NewCipher(r)
	if err != nil {
		return errors.New("otr: cannot create AES cipher from reveal signature message: " + err.Error())
	}
	var iv [aes.BlockSize]byte
	ctr := cipher.NewCTR(aesCipher, iv[:])
	ctr.XORKeyStream(dst, src)
	return nil
}

func sha256Sum(x []byte) []byte {
	out := sha256.Sum256(x)
	return out[:]
}

func (ake *AKE) calcAKEKeys(s *big.Int) {
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

func (ake *AKE) calcDHSharedSecret(xKnown bool) (*big.Int, error) {
	if xKnown {
		if ake.gy == nil {
			return nil, errors.New("missing gy")
		}

		if ake.x == nil {
			return nil, errors.New("missing x")
		}

		return new(big.Int).Exp(ake.gy, ake.x, p), nil
	}

	return new(big.Int).Exp(ake.gx, ake.y, p), nil
}

func (ake *AKE) generateEncryptedSignature(key *akeKeys, xFirst bool) ([]byte, error) {
	verifyData, err := ake.generateVerifyData(xFirst)
	if err != nil {
		return nil, err
	}

	mb := sumHMAC(key.m1[:], verifyData)
	xb := ake.calcXb(key, mb, xFirst)
	return appendData(nil, xb), nil
}

func (ake *AKE) generateVerifyData(xFirst bool) ([]byte, error) {
	var verifyData []byte

	if ake.gy == nil {
		return nil, errors.New("missing gy")
	}

	if ake.gx == nil {
		return nil, errors.New("missing gx")
	}

	if ake.ourKey == nil {
		return nil, errors.New("missing ourKey")
	}

	if xFirst {
		verifyData = appendMPI(verifyData, ake.gx)
		verifyData = appendMPI(verifyData, ake.gy)
	} else {
		verifyData = appendMPI(verifyData, ake.gy)
		verifyData = appendMPI(verifyData, ake.gx)
	}

	publicKey := ake.ourKey.PublicKey.serialize()
	verifyData = append(verifyData, publicKey...)

	return appendWord(verifyData, ake.myKeyID), nil
}

func sumHMAC(key, data []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(data)

	return mac.Sum(nil)
}

func (ake *AKE) calcXb(key *akeKeys, mb []byte, xFirst bool) []byte {
	var sigb []byte
	xb := ake.ourKey.PublicKey.serialize()
	xb = appendWord(xb, ake.myKeyID)

	sigb, _ = ake.ourKey.sign(ake.rand(), mb)
	xb = append(xb, sigb...)

	aesCipher, err := aes.NewCipher(key.c[:])
	if err != nil {
		panic(err.Error())
	}

	var iv [aes.BlockSize]byte
	ctr := cipher.NewCTR(aesCipher, iv[:])
	ctr.XORKeyStream(xb, xb)

	return xb
}

func (ake *AKE) dhCommitMessage() ([]byte, error) {
	ake.myKeyID = 0

	x, err := ake.generateRandBigInt()
	if err != nil {
		return nil, err
	}

	ake.x = x
	ake.gx = new(big.Int).Exp(g1, ake.x, p)
	ake.generateRandBytes(ake.r[:])
	if ake.encryptedGx, err = encrypt(ake.r[:], ake.gx.Bytes()); err != nil {
		return nil, err
	}

	return ake.serializeDHCommit(), nil
}

func (ake *AKE) serializeDHCommit() []byte {
	var out []byte

	out = appendShort(out, ake.protocolVersion())
	out = append(out, msgTypeDHCommit)
	if ake.needInstanceTag() {
		out = appendWord(out, ake.senderInstanceTag)
		out = appendWord(out, ake.receiverInstanceTag)
	}
	out = appendData(out, ake.encryptedGx)
	ake.hashedGx = sha256Sum(ake.gx.Bytes())
	out = appendData(out, ake.hashedGx)

	return out
}

func (ake *AKE) dhKeyMessage() ([]byte, error) {
	y, err := ake.generateRandBigInt()
	if err != nil {
		return nil, err
	}

	ake.y = y
	ake.gy = new(big.Int).Exp(g1, ake.y, p)
	return ake.serializeDHKey()
}

func (ake *AKE) serializeDHKey() ([]byte, error) {
	var out []byte

	out = appendShort(out, ake.protocolVersion())
	out = append(out, msgTypeDHKey)

	if ake.needInstanceTag() {
		out = appendWord(out, ake.senderInstanceTag)
		out = appendWord(out, ake.receiverInstanceTag)
	}

	out = appendMPI(out, ake.gy)

	return out, nil
}

func (ake *AKE) revealSigMessage() ([]byte, error) {
	s, err := ake.calcDHSharedSecret(true)
	if err != nil {
		return nil, err
	}

	ake.calcAKEKeys(s)
	var out []byte
	out = appendShort(out, ake.protocolVersion())
	out = append(out, msgTypeRevealSig)
	if ake.needInstanceTag() {
		out = appendWord(out, ake.senderInstanceTag)
		out = appendWord(out, ake.receiverInstanceTag)
	}
	out = appendData(out, ake.r[:])
	encryptedSig, err := ake.generateEncryptedSignature(&ake.revealKey, true)
	if err != nil {
		return nil, err
	}

	macSig := sumHMAC(ake.revealKey.m2[:], encryptedSig)
	out = append(out, encryptedSig...)
	out = append(out, macSig[:20]...)

	return out, nil
}

func (ake *AKE) sigMessage() ([]byte, error) {
	s, err := ake.calcDHSharedSecret(false)
	if err != nil {
		return nil, err
	}

	ake.calcAKEKeys(s)
	var out []byte
	out = appendShort(out, ake.protocolVersion())
	out = append(out, msgTypeSig)
	if ake.needInstanceTag() {
		out = appendWord(out, ake.senderInstanceTag)
		out = appendWord(out, ake.receiverInstanceTag)
	}

	encryptedSig, err := ake.generateEncryptedSignature(&ake.sigKey, false)
	if err != nil {
		return nil, err
	}

	macSig := sumHMAC(ake.sigKey.m2[:], encryptedSig)
	out = append(out, encryptedSig...)
	out = append(out, macSig[:20]...)

	return out, nil
}

func (ake *AKE) processDHKey(in []byte) (isSame bool, err error) {
	_, gy := extractMPI(in, 0)
	if lt(gy, g1) || gt(gy, pMinusTwo) {
		err = errors.New("otr: DH value out of range")
		return
	}

	//NOTE: This keeps only the first Gy received
	//Not sure if this is part of the spec,
	//or simply a crypto/otr safeguard
	if ake.gy != nil {
		isSame = eq(ake.gy, gy)
		return
	}
	ake.gy = gy
	return
}

func (ake *AKE) checkDecryptedGx(decryptedGx []byte) error {
	digest := sha256Sum(decryptedGx)
	if len(digest) != len(ake.digest) || subtle.ConstantTimeCompare(digest, ake.digest[:]) == 0 {
		return errors.New("otr: bad commit MAC in reveal signature message")
	}
	return nil
}

func extractGx(decryptedGx []byte) (*big.Int, error) {
	index, gx := extractMPI(decryptedGx, 0)
	if len(decryptedGx) > index {
		return gx, errors.New("otr: gx corrupt after decryption")
	}
	if gx.Cmp(g1) < 0 || gx.Cmp(pMinusTwo) > 0 {
		return gx, errors.New("otr: DH value out of range")
	}
	return gx, nil
}

func (ake *AKE) processRevealSig(in []byte) (err error) {
	index, r := extractData(in, 0)
	index, encryptedSig := extractData(in, index)
	theirMAC := in[index:]
	if len(theirMAC) != 20 {
		return errors.New("otr: corrupt reveal signature message")
	}
	decryptedGx := make([]byte, len(ake.encryptedGx))
	if err = decrypt(r, decryptedGx, ake.encryptedGx); err != nil {
		return
	}
	if err = ake.checkDecryptedGx(decryptedGx); err != nil {
		return
	}
	if ake.gx, err = extractGx(decryptedGx); err != nil {
		return
	}
	var s *big.Int
	if s, err = ake.calcDHSharedSecret(false); err != nil {
		return
	}
	ake.calcAKEKeys(s)

	if err = ake.processEncryptedSig(encryptedSig, theirMAC, &ake.revealKey, true /* gx comes first */); err != nil {
		return errors.New("otr: in reveal signature message: " + err.Error())
	}

	//	ake.theirCurrentDHPub = ake.gx
	//	ake.theirLastDHPub = nil

	return nil
}

func (ake *AKE) processEncryptedSig(encryptedSig []byte, theirMAC []byte, revealKey *akeKeys, xFirst bool) error {
	return nil
}
