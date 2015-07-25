package otr3

import (
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

func (ake *conversation) calcAKEKeys(s *big.Int) {
	ake.ssid, ake.revealKey, ake.sigKey = calculateAKEKeys(s)
}

func (ake *conversation) setSecretExponent(val *big.Int) {
	ake.secretExponent = val
	ake.ourPublicValue = modExp(g1, val)
}

func (ake *conversation) calcDHSharedSecret() *big.Int {
	return modExp(ake.theirPublicValue, ake.secretExponent)
}

func (ake *conversation) generateEncryptedSignature(key *akeKeys) ([]byte, error) {
	verifyData := appendAll(ake.ourPublicValue, ake.theirPublicValue, &ake.ourKey.PublicKey, ake.keys.ourKeyID)

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

func (ake *conversation) calcXb(key *akeKeys, mb []byte) ([]byte, error) {
	xb := ake.ourKey.PublicKey.serialize()
	xb = appendWord(xb, ake.keys.ourKeyID)

	sigb, err := ake.ourKey.sign(ake.rand(), mb)
	if err != nil {
		if err == io.ErrUnexpectedEOF {
			return nil, errShortRandomRead
		}
		return nil, err
	}

	// this error can't happen, since key.c is fixed to the correct size
	xb, _ = encrypt(key.c[:], append(xb, sigb...))

	return xb, nil
}

func (ake *conversation) randomInto(b []byte) error {
	if _, err := io.ReadFull(ake.rand(), b); err != nil {
		return errShortRandomRead
	}
	return nil
}

// dhCommitMessage = bob = x
// Bob ---- DH Commit -----------> Alice
func (ake *conversation) dhCommitMessage() ([]byte, error) {
	ake.keys.ourKeyID = 0

	x, ok := ake.randMPI(make([]byte, 40))
	if !ok {
		return nil, errShortRandomRead
	}

	ake.setSecretExponent(x)

	if err := ake.randomInto(ake.r[:]); err != nil {
		return nil, err
	}

	// this can't return an error, since ake.r is of a fixed size that is always correct
	ake.encryptedGx, _ = encrypt(ake.r[:], appendMPI(nil, ake.ourPublicValue))
	return ake.serializeDHCommit(ake.ourPublicValue), nil
}

func (ake *conversation) serializeDHCommit(public *big.Int) []byte {
	dhCommitMsg := dhCommit{
		messageHeader: ake.messageHeader(),
		gx:            public,
		encryptedGx:   ake.encryptedGx,
	}
	return dhCommitMsg.serialize()
}

// dhKeyMessage = alice = y
// Alice -- DH Key --------------> Bob
func (ake *conversation) dhKeyMessage() ([]byte, error) {
	y, ok := ake.randMPI(make([]byte, 40)[:])

	if !ok {
		return nil, errShortRandomRead
	}

	ake.setSecretExponent(y)
	return ake.serializeDHKey(), nil
}

func (ake *conversation) serializeDHKey() []byte {
	dhKeyMsg := dhKey{
		messageHeader: ake.messageHeader(),
		gy:            ake.ourPublicValue,
	}

	return dhKeyMsg.serialize()
}

// revealSigMessage = bob = x
// Bob ---- Reveal Signature ----> Alice
func (ake *conversation) revealSigMessage() ([]byte, error) {
	ake.calcAKEKeys(ake.calcDHSharedSecret())
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
func (ake *conversation) sigMessage() ([]byte, error) {
	ake.calcAKEKeys(ake.calcDHSharedSecret())
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
func (ake *conversation) processDHCommit(msg []byte) error {
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
func (ake *conversation) processDHKey(msg []byte) (isSame bool, err error) {
	dhKeyMsg := dhKey{}
	err = chainErrors(ake.ensureValidMessage, dhKeyMsg.deserialize, msg)
	if err != nil {
		return false, err
	}
	//NOTE: This keeps only the first Gy received
	//Not sure if this is part of the spec,
	//or simply a crypto/otr safeguard
	if ake.theirPublicValue != nil {
		isSame = eq(ake.theirPublicValue, dhKeyMsg.gy)
		return
	}
	ake.theirPublicValue = dhKeyMsg.gy
	return
}

// processRevealSig = alice = y
// Bob ---- Reveal Signature ----> Alice
func (ake *conversation) processRevealSig(msg []byte) (err error) {
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

	if ake.theirPublicValue, err = extractGx(decryptedGx); err != nil {
		return
	}

	ake.calcAKEKeys(ake.calcDHSharedSecret())
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

func (ake *conversation) ensureValidMessage(msg []byte) ([]byte, error) {
	if len(msg) < ake.version.headerLen() {
		return nil, errInvalidOTRMessage
	}
	return msg[ake.version.headerLen():], nil
}

// processSig = bob = x
// Alice -- Signature -----------> Bob
func (ake *conversation) processSig(msg []byte) (err error) {
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

func (ake *conversation) checkedSignatureVerification(mb, sig []byte) error {
	rest, ok := ake.theirKey.verify(mb, sig)
	if !ok {
		return errors.New("bad signature in encrypted signature")
	}
	if len(rest) > 0 {
		return errCorruptEncryptedSignature
	}
	return nil
}

func verifyEncryptedSignatureMAC(encryptedSig []byte, theirMAC []byte, keys *akeKeys) error {
	tomac := appendData(nil, encryptedSig)
	myMAC := sumHMAC(keys.m2[:], tomac)[:20]

	if len(myMAC) != len(theirMAC) || subtle.ConstantTimeCompare(myMAC, theirMAC) == 0 {
		return errors.New("bad signature MAC in encrypted signature")
	}

	return nil
}

func (ake *conversation) parseTheirKey(key []byte) (sig []byte, keyID uint32, err error) {
	ake.theirKey = &PublicKey{}
	rest, ok1 := ake.theirKey.parse(key)
	sig, keyID, ok2 := extractWord(rest)

	if !ok1 || !ok2 {
		return nil, 0, errCorruptEncryptedSignature
	}

	return
}

func (ake *conversation) expectedMessageHMAC(keyID uint32, keys *akeKeys) []byte {
	verifyData := appendAll(ake.theirPublicValue, ake.ourPublicValue, ake.theirKey, keyID)
	return sumHMAC(keys.m1[:], verifyData)
}

func (ake *conversation) processEncryptedSig(encryptedSig []byte, theirMAC []byte, keys *akeKeys) error {
	if err := verifyEncryptedSignatureMAC(encryptedSig, theirMAC, keys); err != nil {
		return err
	}

	decryptedSig := encryptedSig
	if err := decrypt(keys.c[:], decryptedSig, encryptedSig); err != nil {
		return err
	}

	sig, keyID, err := ake.parseTheirKey(decryptedSig)
	if err != nil {
		return err
	}

	mb := ake.expectedMessageHMAC(keyID, keys)
	if err := ake.checkedSignatureVerification(mb, sig); err != nil {
		return err
	}

	ake.keys.theirKeyID = keyID

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

func checkDecryptedGx(decryptedGx, hashedGx []byte) error {
	digest := sha256.Sum256(decryptedGx)

	if subtle.ConstantTimeCompare(digest[:], hashedGx[:]) == 0 {
		return errors.New("otr: bad commit MAC in reveal signature message")
	}

	return nil
}
