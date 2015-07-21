package otr3

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"hash"
	"io"
	"math/big"
)

const (
	msgTypeData      = byte(3)
	msgTypeDHCommit  = byte(2)
	msgTypeDHKey     = byte(10)
	msgTypeRevealSig = byte(17)
	msgTypeSig       = byte(18)
)

// AKE is authenticated key exchange context
type AKE struct {
	akeContext
	revealKey            akeKeys
	ssid                 [8]byte
	ourKeyID, theirKeyID uint32
}

type akeKeys struct {
	c      [16]byte
	m1, m2 [32]byte
}

func (ake *AKE) calcAKEKeys(s *big.Int) {
	secbytes := appendMPI(nil, s)
	h := sha256.New()
	keys := h2(0x01, secbytes, h)
	copy(ake.ssid[:], h2(0x00, secbytes, h)[:8])
	copy(ake.revealKey.c[:], keys[:16])
	copy(ake.sigKey.c[:], keys[16:])
	copy(ake.revealKey.m1[:], h2(0x02, secbytes, h))
	copy(ake.revealKey.m2[:], h2(0x03, secbytes, h))
	copy(ake.sigKey.m1[:], h2(0x04, secbytes, h))
	copy(ake.sigKey.m2[:], h2(0x05, secbytes, h))
}

func (ake *AKE) calcDHSharedSecret(xKnown bool) *big.Int {
	if xKnown {
		return modExp(ake.gy, ake.x)
	}

	return modExp(ake.gx, ake.y)
}

func (ake *AKE) generateEncryptedSignature(key *akeKeys, xFirst bool) ([]byte, error) {
	verifyData := ake.generateVerifyData(xFirst, &ake.ourKey.PublicKey, ake.ourKeyID)

	mb := sumHMAC(key.m1[:], verifyData)
	xb, err := ake.calcXb(key, mb, xFirst)

	if err != nil {
		return nil, err
	}

	return appendData(nil, xb), nil
}

func (ake *AKE) generateVerifyData(xFirst bool, publicKey *PublicKey, keyID uint32) []byte {
	var verifyData []byte

	if xFirst {
		verifyData = appendMPI(verifyData, ake.gx)
		verifyData = appendMPI(verifyData, ake.gy)
	} else {
		verifyData = appendMPI(verifyData, ake.gy)
		verifyData = appendMPI(verifyData, ake.gx)
	}

	verifyData = append(verifyData, publicKey.serialize()...)

	return appendWord(verifyData, keyID)
}

func (ake *AKE) calcXb(key *akeKeys, mb []byte, xFirst bool) ([]byte, error) {
	xb := ake.ourKey.PublicKey.serialize()
	xb = appendWord(xb, ake.ourKeyID)

	sigb, err := ake.ourKey.sign(ake.rand(), mb)
	if err != nil {
		return nil, err
	}

	xb = append(xb, sigb...)

	// this error can't happen, since key.c is fixed to the correct size
	aesCipher, _ := aes.NewCipher(key.c[:])

	ctr := cipher.NewCTR(aesCipher, make([]byte, aes.BlockSize))
	ctr.XORKeyStream(xb, xb)

	return xb, nil
}

func (ake *AKE) dhCommitMessage() ([]byte, error) {
	ake.ourKeyID = 0

	x, ok := ake.randMPI(make([]byte, 40))
	if !ok {
		return nil, errors.New("otr: short read from random source")
	}

	ake.x = x
	ake.gx = modExp(g1, ake.x)

	if _, err := io.ReadFull(ake.rand(), ake.r[:]); err != nil {
		return nil, errors.New("otr: short read from random source")
	}

	// this can't return an error, since ake.r is of a fixed size that is always correct
	ake.encryptedGx, _ = encrypt(ake.r[:], appendMPI(nil, ake.gx))
	return ake.serializeDHCommit(), nil
}

func (ake *AKE) serializeDHCommit() []byte {
	out := appendShort(nil, ake.protocolVersion())
	out = append(out, msgTypeDHCommit)
	if ake.needInstanceTag() {
		out = appendWord(out, ake.senderInstanceTag)
		out = appendWord(out, ake.receiverInstanceTag)
	}
	out = appendData(out, ake.encryptedGx)
	ake.hashedGx = sha256Sum(appendMPI(nil, ake.gx))
	out = appendData(out, ake.hashedGx[:])

	return out
}

func (ake *AKE) dhKeyMessage() ([]byte, error) {
	y, ok := ake.randMPI(make([]byte, 40)[:])

	if !ok {
		return nil, errors.New("otr: short read from random source")
	}

	ake.y = y
	ake.gy = modExp(g1, ake.y)
	return ake.serializeDHKey(), nil
}

func (ake *AKE) serializeDHKey() []byte {
	out := appendShort(nil, ake.protocolVersion())
	out = append(out, msgTypeDHKey)

	if ake.needInstanceTag() {
		out = appendWord(out, ake.senderInstanceTag)
		out = appendWord(out, ake.receiverInstanceTag)
	}

	return appendMPI(out, ake.gy)
}

func (ake *AKE) revealSigMessage() ([]byte, error) {
	ake.calcAKEKeys(ake.calcDHSharedSecret(true))

	out := appendShort(nil, ake.protocolVersion())
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
	ake.calcAKEKeys(ake.calcDHSharedSecret(false))
	out := appendShort(nil, ake.protocolVersion())
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

func (ake *AKE) processDHKey(msg []byte) (isSame bool, err error) {
	if len(msg) < ake.headerLen() {
		return false, errors.New("otr: invalid OTR message")
	}

	_, gy, ok := extractMPI(msg[ake.headerLen():])

	if !ok {
		return false, errors.New("otr: corrupt DH key message")
	}

	// TODO: is this only for otrv3 or for v2 too?
	if lt(gy, g1) || gt(gy, pMinusTwo) {
		return false, errors.New("otr: DH value out of range")
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

func (ake *AKE) processDHCommit(msg []byte) error {
	if len(msg) < ake.headerLen() {
		return errors.New("otr: invalid OTR message")
	}

	var ok1 bool
	msg, ake.encryptedGx, ok1 = extractData(msg[ake.headerLen():])
	_, h, ok2 := extractData(msg)
	if !ok1 || !ok2 {
		return errors.New("otr: corrupt DH commit message")
	}
	copy(ake.hashedGx[:], h)
	return nil
}

func (ake *AKE) processRevealSig(msg []byte) (err error) {
	if len(msg) < ake.headerLen() {
		return errors.New("otr: invalid OTR message")
	}

	in, r, ok1 := extractData(msg[ake.headerLen():])
	theirMAC, encryptedSig, ok2 := extractData(in)

	if !ok1 || !ok2 || len(theirMAC) != 20 {
		return errors.New("otr: corrupt reveal signature message")
	}

	decryptedGx := make([]byte, len(ake.encryptedGx))
	if err = decrypt(r, decryptedGx, ake.encryptedGx); err != nil {
		return
	}
	if err = checkDecryptedGx(decryptedGx, ake.hashedGx[:]); err != nil {
		return
	}
	if ake.gx, err = extractGx(decryptedGx); err != nil {
		return
	}

	ake.calcAKEKeys(ake.calcDHSharedSecret(false))

	if err = ake.processEncryptedSig(encryptedSig, theirMAC, &ake.revealKey, true /* gx comes first */); err != nil {
		return errors.New("otr: in reveal signature message: " + err.Error())
	}

	//	ake.theirCurrentDHPub = ake.gx
	//	ake.theirLastDHPub = nil

	return nil
}

func (ake *AKE) processSig(msg []byte) error {
	if len(msg) < ake.headerLen() {
		return errors.New("otr: invalid OTR message")
	}

	theirMAC, encryptedSig, ok := extractData(msg[ake.headerLen():])

	if !ok || len(theirMAC) != 20 {
		return errors.New("otr: corrupt signature message")
	}

	if err := ake.processEncryptedSig(encryptedSig, theirMAC, &ake.sigKey, false /* gy comes first */); err != nil {
		return errors.New("otr: in signature message: " + err.Error())
	}

	//ake.theirCurrentDHPub = ake.gy
	//ake.theirLastDHPub = nil

	return nil
}

func (ake *AKE) processEncryptedSig(encryptedSig []byte, theirMAC []byte, keys *akeKeys, xFirst bool) error {
	tomac := appendData(nil, encryptedSig)
	myMAC := sumHMAC(keys.m2[:], tomac)[:20]

	if len(myMAC) != len(theirMAC) || subtle.ConstantTimeCompare(myMAC, theirMAC) == 0 {
		return errors.New("bad signature MAC in encrypted signature")
	}

	decryptedSig := encryptedSig
	if err := decrypt(keys.c[:], decryptedSig, encryptedSig); err != nil {
		return err
	}

	ake.theirKey = &PublicKey{}

	nextPoint, ok1 := ake.theirKey.parse(decryptedSig)

	_, keyID, ok2 := extractWord(nextPoint)

	if !ok1 || !ok2 || len(nextPoint) < 4 {
		return errors.New("otr: corrupt encrypted signature")
	}

	sig := nextPoint[4:]

	verifyData := ake.generateVerifyData(xFirst, ake.theirKey, keyID)
	mb := sumHMAC(keys.m1[:], verifyData)

	rest, ok := ake.theirKey.verify(mb, sig)
	if !ok {
		return errors.New("bad signature in encrypted signature")
	}
	if len(rest) > 0 {
		return errors.New("corrupt encrypted signature")
	}

	ake.theirKeyID = keyID
	//zero(ake.theirLastCtr[:])
	return nil
}

func extractGx(decryptedGx []byte) (*big.Int, error) {
	newData, gx, ok := extractMPI(decryptedGx)
	if !ok || len(newData) > 0 {
		return gx, errors.New("otr: gx corrupt after decryption")
	}

	// TODO: is this valid in otrv2 or only otrv3?
	if lt(gx, g1) || gt(gx, pMinusTwo) {
		return gx, errors.New("otr: DH value out of range")
	}
	return gx, nil
}

func sumHMAC(key, data []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(data)
	return mac.Sum(nil)
}

func sha256Sum(x []byte) [sha256.Size]byte {
	return sha256.Sum256(x)
}

func h2(b byte, secbytes []byte, h hash.Hash) []byte {
	h.Reset()
	h.Write([]byte{b})
	h.Write(secbytes[:])
	return h.Sum(nil)
}

func encrypt(r, gxMPI []byte) (dst []byte, err error) {
	aesCipher, err := aes.NewCipher(r)
	if err != nil {
		return nil, err
	}

	dst = make([]byte, len(gxMPI))
	iv := dst[:aes.BlockSize]
	stream := cipher.NewCTR(aesCipher, iv)
	stream.XORKeyStream(dst, gxMPI)

	return dst, nil
}

func decrypt(r, dst, src []byte) error {
	aesCipher, err := aes.NewCipher(r)
	if err != nil {
		return errors.New("otr: cannot create AES cipher from reveal signature message: " + err.Error())
	}
	var iv [aes.BlockSize]byte
	ctr := cipher.NewCTR(aesCipher, iv[:])
	ctr.XORKeyStream(dst, src)
	return nil
}

func checkDecryptedGx(decryptedGx, hashedGx []byte) error {
	digest := sha256Sum(decryptedGx)

	if subtle.ConstantTimeCompare(digest[:], hashedGx[:]) == 0 {
		return errors.New("otr: bad commit MAC in reveal signature message")
	}

	return nil
}
