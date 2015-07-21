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
	verifyData := ake.generateVerifyData(xFirst, &ake.ourKey.PublicKey, ake.ourKeyID)

	mb := sumHMAC(key.m1[:], verifyData)
	xb := ake.calcXb(key, mb, xFirst)
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

func (ake *AKE) calcXb(key *akeKeys, mb []byte, xFirst bool) []byte {
	// TODO: errors?
	var sigb []byte
	xb := ake.ourKey.PublicKey.serialize()
	xb = appendWord(xb, ake.ourKeyID)

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

func (ake *AKE) generateDHCommitMessage() ([]byte, error) {
	// TODO: errors?
	ake.ourKeyID = 0

	x, ok := ake.randMPI(make([]byte, 40)[:])
	if !ok {
		return nil, errors.New("otr: short read from random source")
	}
	ake.x = x
	ake.gx = new(big.Int).Exp(g1, ake.x, p)
	io.ReadFull(ake.rand(), ake.r[:])
	ake.encryptedGx, _ = encrypt(ake.r[:], appendMPI([]byte{}, ake.gx))
	ake.hashedGx = sha256Sum(appendMPI(nil, ake.gx))

	dhCommitMsg := dhCommit{
		protocolVersion:     ake.protocolVersion(),
		needInstanceTag:     ake.needInstanceTag(),
		senderInstanceTag:   ake.senderInstanceTag,
		receiverInstanceTag: ake.receiverInstanceTag,
		gx:                  ake.gx,
		encryptedGx:         ake.encryptedGx,
	}

	return dhCommitMsg.serialize(), nil
}

func (ake *AKE) serializeDHCommit() []byte {

	dhCommitMsg := dhCommit{
		protocolVersion:     ake.protocolVersion(),
		needInstanceTag:     ake.needInstanceTag(),
		senderInstanceTag:   ake.senderInstanceTag,
		receiverInstanceTag: ake.receiverInstanceTag,
		gx:                  ake.gx,
		encryptedGx:         ake.encryptedGx,
	}

	return dhCommitMsg.serialize()
}

func (ake *AKE) generateDHKeyMessage() ([]byte, error) {
	// TODO: errors?
	y, ok := ake.randMPI(make([]byte, 40)[:])

	if !ok {
		return nil, errors.New("otr: short read from random source")
	}

	ake.y = y
	ake.gy = new(big.Int).Exp(g1, ake.y, p)

	dhKeyMsg := dhKey{
		protocolVersion:     ake.protocolVersion(),
		needInstanceTag:     ake.needInstanceTag(),
		senderInstanceTag:   ake.senderInstanceTag,
		receiverInstanceTag: ake.receiverInstanceTag,
		gy:                  ake.gy,
	}
	return dhKeyMsg.serialize(), nil
}

func (ake *AKE) serializeDHKey() ([]byte, error) {
	// TODO: errors?

	dhKeyMsg := dhKey{
		protocolVersion:     ake.protocolVersion(),
		needInstanceTag:     ake.needInstanceTag(),
		senderInstanceTag:   ake.senderInstanceTag,
		receiverInstanceTag: ake.receiverInstanceTag,
		gy:                  ake.gy,
	}
	return dhKeyMsg.serialize(), nil
}

func (ake *AKE) generateRevealSigMessage() ([]byte, error) {
	// TODO: errors?
	s, err := ake.calcDHSharedSecret(true)
	if err != nil {
		return nil, err
	}

	ake.calcAKEKeys(s)
	encryptedSig, err := ake.generateEncryptedSignature(&ake.revealKey, true)
	if err != nil {
		return nil, err
	}
	return ake.serializeRevealSig(encryptedSig), nil
}

func (ake *AKE) serializeRevealSig(encryptedSig []byte) []byte {
	var out []byte
	out = appendShort(out, ake.protocolVersion())
	out = append(out, msgTypeRevealSig)
	if ake.needInstanceTag() {
		out = appendWord(out, ake.senderInstanceTag)
		out = appendWord(out, ake.receiverInstanceTag)
	}
	out = appendData(out, ake.r[:])

	macSig := sumHMAC(ake.revealKey.m2[:], encryptedSig)
	out = append(out, encryptedSig...)
	out = append(out, macSig[:20]...)
	return out
}

func (ake *AKE) generateSigMessage() ([]byte, error) {
	// TODO: errors?
	s, err := ake.calcDHSharedSecret(false)
	if err != nil {
		return nil, err
	}

	ake.calcAKEKeys(s)
	encryptedSig, err := ake.generateEncryptedSignature(&ake.sigKey, false)
	if err != nil {
		return nil, err
	}

	return ake.serializeSig(encryptedSig), nil
}

func (ake *AKE) serializeSig(encryptedSig []byte) []byte {
	var out []byte
	out = appendShort(out, ake.protocolVersion())
	out = append(out, msgTypeSig)
	if ake.needInstanceTag() {
		out = appendWord(out, ake.senderInstanceTag)
		out = appendWord(out, ake.receiverInstanceTag)
	}
	macSig := sumHMAC(ake.sigKey.m2[:], encryptedSig)
	out = append(out, encryptedSig...)
	out = append(out, macSig[:20]...)
	return out
}

func (ake *AKE) processDHCommit(msg []byte) error {
	dhCommitMsg := dhCommit{headerLen: ake.headerLen()}
	err := dhCommitMsg.deserialize(msg)
	ake.encryptedGx = dhCommitMsg.encryptedGx
	ake.hashedGx = dhCommitMsg.hashedGx
	return err
}

func (ake *AKE) processDHKey(msg []byte) (isSame bool, err error) {
	// TODO: errors?
	in := msg[ake.headerLen():]
	_, gy, _ := extractMPI(in)

	// TODO: is this only for otrv3 or for v2 too?
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
	// TODO: errors?
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
	nextPoint, _ := ake.theirKey.parse(decryptedSig)

	_, keyID, ok := extractWord(nextPoint)

	if !ok {
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
