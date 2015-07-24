package otr3

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
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
	revealKey akeKeys
	ssid      [8]byte
}

func (ake *AKE) calcAKEKeys(s *big.Int) {
	ake.ssid, ake.revealKey, ake.sigKey = calculateAKEKeys(s)
}

func (ake *akeContext) getGY() *big.Int {
	return ake._gy
}

func (ake *akeContext) getGX() *big.Int {
	return ake._gx
}

func (ake *akeContext) getExponent() *big.Int {
	return ake.secretExponent
}

func (ake *akeContext) getTheirPublicValue() *big.Int {
	return ake._their
}

func (ake *akeContext) getOurPublicValue() *big.Int {
	return ake._our
}

func (ake *akeContext) getX() *big.Int {
	return ake.secretExponent
}

func (ake *akeContext) getY() *big.Int {
	return ake.secretExponent
}

func (ake *akeContext) setX(val *big.Int) {
	ake.secretExponent = val
	ake.setGXOur(modExp(g1, val))
}

func (ake *akeContext) setY(val *big.Int) {
	ake.secretExponent = val
	ake.setGYOur(modExp(g1, val))
}

func (ake *akeContext) setGXTheir(val *big.Int) {
	ake._gx = val
	ake._their = val
}

func (ake *akeContext) setGXOur(val *big.Int) {
	ake._gx = val
	ake._our = val
}

func (ake *akeContext) setGYTheir(val *big.Int) {
	ake._gy = val
	ake._their = val
}

func (ake *akeContext) setGYOur(val *big.Int) {
	ake._gy = val
	ake._our = val
}

func (ake *AKE) calcDHSharedSecret(xKnown bool) *big.Int {
	return modExp(ake.getTheirPublicValue(), ake.getExponent())
}

func (ake *AKE) generateEncryptedSignature(key *akeKeys) ([]byte, error) {
	verifyData := appendAll(ake.getOurPublicValue(), ake.getTheirPublicValue(), &ake.ourKey.PublicKey, ake.ourKeyID)

	mb := sumHMAC(key.m1[:], verifyData)
	xb, err := ake.calcXb(key, mb)

	if err != nil {
		return nil, err
	}

	return appendData(nil, xb), nil
}
func appendAll(one, two *big.Int, publicKey *PublicKey, keyID uint32) []byte {
	return appendWord(append(appendMPI(appendMPI(nil, one), two), publicKey.serialize()...), keyID)
}

func (ake *AKE) calcXb(key *akeKeys, mb []byte) ([]byte, error) {
	xb := ake.ourKey.PublicKey.serialize()
	xb = appendWord(xb, ake.ourKeyID)

	sigb, err := ake.ourKey.sign(ake.rand(), mb)
	if err != nil {
		if err == io.ErrUnexpectedEOF {
			return nil, errShortRandomRead
		}
		return nil, err
	}

	xb = append(xb, sigb...)

	// this error can't happen, since key.c is fixed to the correct size
	aesCipher, _ := aes.NewCipher(key.c[:])

	ctr := cipher.NewCTR(aesCipher, make([]byte, aes.BlockSize))
	ctr.XORKeyStream(xb, xb)

	return xb, nil
}

// dhCommitMessage = bob = x
// Bob ---- DH Commit -----------> Alice
func (ake *AKE) dhCommitMessage() ([]byte, error) {
	ake.ourKeyID = 0

	x, ok := ake.randMPI(make([]byte, 40))
	if !ok {
		return nil, errShortRandomRead
	}

	ake.setX(x)

	if _, err := io.ReadFull(ake.rand(), ake.r[:]); err != nil {
		return nil, errShortRandomRead
	}

	// this can't return an error, since ake.r is of a fixed size that is always correct
	ake.encryptedGx, _ = encrypt(ake.r[:], appendMPI(nil, ake.getOurPublicValue()))

	dhCommitMsg := dhCommit{
		messageHeader: ake.messageHeader(),
		gx:            ake.getOurPublicValue(),
		encryptedGx:   ake.encryptedGx,
	}
	return dhCommitMsg.serialize(), nil
}

func (ake *AKE) serializeDHCommit() []byte {
	dhCommitMsg := dhCommit{
		messageHeader: ake.messageHeader(),
		gx:            ake.getTheirPublicValue(),
		encryptedGx:   ake.encryptedGx,
	}
	return dhCommitMsg.serialize()
}

// dhKeyMessage = alice = y
// Alice -- DH Key --------------> Bob
func (ake *AKE) dhKeyMessage() ([]byte, error) {
	y, ok := ake.randMPI(make([]byte, 40)[:])

	if !ok {
		return nil, errShortRandomRead
	}

	ake.setY(y)
	return ake.serializeDHKey(), nil
}

func (ake *AKE) serializeDHKey() []byte {
	dhKeyMsg := dhKey{
		messageHeader: ake.messageHeader(),
		gy:            ake.getOurPublicValue(),
	}

	return dhKeyMsg.serialize()
}

// revealSigMessage = bob = x
// Bob ---- Reveal Signature ----> Alice
func (ake *AKE) revealSigMessage() ([]byte, error) {
	ake.calcAKEKeys(ake.calcDHSharedSecret(true))
	encryptedSig, err := ake.generateEncryptedSignature(&ake.revealKey)
	if err != nil {
		return nil, err
	}
	macSig := sumHMAC(ake.revealKey.m2[:], encryptedSig)

	revealSigMsg := revealSig{
		messageHeader: ake.messageHeader(),
		r:             ake.r,
		encryptedSig:  encryptedSig,
		macSig:        macSig,
	}
	return revealSigMsg.serialize(), nil
}

// sigMessage = alice = y
// Alice -- Signature -----------> Bob
func (ake *AKE) sigMessage() ([]byte, error) {
	ake.calcAKEKeys(ake.calcDHSharedSecret(false))
	encryptedSig, err := ake.generateEncryptedSignature(&ake.sigKey)
	if err != nil {
		return nil, err
	}
	macSig := sumHMAC(ake.sigKey.m2[:], encryptedSig)
	sigMsg := sig{
		messageHeader: ake.messageHeader(),
		encryptedSig:  encryptedSig,
		macSig:        macSig,
	}

	return sigMsg.serialize(), nil
}

// processDHCommit = alice = y
// Bob ---- DH Commit -----------> Alice
func (ake *AKE) processDHCommit(msg []byte) error {
	dhCommitMsg := dhCommit{}
	err := chainErrors(ake.ensureValidMessage, dhCommitMsg.deserialize, msg)
	if err != nil {
		return err
	}
	ake.encryptedGx = dhCommitMsg.encryptedGx
	ake.hashedGx = dhCommitMsg.hashedGx
	return err
}

// processDHKey = bob = x
// Alice -- DH Key --------------> Bob
func (ake *AKE) processDHKey(msg []byte) (isSame bool, err error) {
	dhKeyMsg := dhKey{}
	err = chainErrors(ake.ensureValidMessage, dhKeyMsg.deserialize, msg)
	if err != nil {
		return false, err
	}
	//NOTE: This keeps only the first Gy received
	//Not sure if this is part of the spec,
	//or simply a crypto/otr safeguard
	if ake.getTheirPublicValue() != nil {
		isSame = eq(ake.getTheirPublicValue(), dhKeyMsg.gy)
		return
	}
	ake.setGYTheir(dhKeyMsg.gy)
	return
}

// processRevealSig = alice = y
// Bob ---- Reveal Signature ----> Alice
func (ake *AKE) processRevealSig(msg []byte) (err error) {
	revealSigMsg := revealSig{}
	err = chainErrors(ake.ensureValidMessage, revealSigMsg.deserialize, msg)
	if err != nil {
		return
	}
	r := revealSigMsg.r[:]
	theirMAC := revealSigMsg.macSig
	encryptedSig := revealSigMsg.encryptedSig

	//check Decrypted Gx and signature
	decryptedGx := make([]byte, len(ake.encryptedGx))
	if err = decrypt(r, decryptedGx, ake.encryptedGx); err != nil {
		return
	}
	if err = checkDecryptedGx(decryptedGx, ake.hashedGx[:]); err != nil {
		return
	}
	var tempgx *big.Int
	if tempgx, err = extractGx(decryptedGx); err != nil {
		return
	}
	ake.setGXTheir(tempgx)
	ake.calcAKEKeys(ake.calcDHSharedSecret(false))
	if err = ake.processEncryptedSig(encryptedSig, theirMAC, &ake.revealKey); err != nil {
		return newOtrError("in reveal signature message: " + err.Error())
	}

	return nil
}

func chainErrors(f1 func([]byte) ([]byte, error), f2 func([]byte) error, msg []byte) error {
	res, e1 := f1(msg)
	if e1 != nil {
		return e1
	}
	return f2(res)
}

func (ake *AKE) ensureValidMessage(msg []byte) ([]byte, error) {
	if len(msg) < ake.headerLen() {
		return nil, errInvalidOTRMessage
	}
	return msg[ake.headerLen():], nil
}

// processSig = bob = x
// Alice -- Signature -----------> Bob
func (ake *AKE) processSig(msg []byte) (err error) {
	sigMsg := sig{}
	err = chainErrors(ake.ensureValidMessage, sigMsg.deserialize, msg)
	if err != nil {
		return
	}
	theirMAC := sigMsg.macSig
	encryptedSig := sigMsg.encryptedSig

	if err := ake.processEncryptedSig(encryptedSig, theirMAC, &ake.sigKey); err != nil {
		return errors.New("otr: in signature message: " + err.Error())
	}

	return nil
}

func (ake *AKE) processEncryptedSig(encryptedSig []byte, theirMAC []byte, keys *akeKeys) error {
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
		return errCorruptEncryptedSignature
	}

	sig := nextPoint[4:]

	verifyData := appendAll(ake.getTheirPublicValue(), ake.getOurPublicValue(), ake.theirKey, keyID)

	mb := sumHMAC(keys.m1[:], verifyData)

	rest, ok := ake.theirKey.verify(mb, sig)
	if !ok {
		return errors.New("bad signature in encrypted signature")
	}
	if len(rest) > 0 {
		return errCorruptEncryptedSignature
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

func encrypt(key, data []byte) (dst []byte, err error) {
	aesCipher, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	dst = make([]byte, len(data))
	iv := dst[:aes.BlockSize]
	stream := cipher.NewCTR(aesCipher, iv)
	stream.XORKeyStream(dst, data)

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
