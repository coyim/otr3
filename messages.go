package otr3

import (
	"crypto/aes"
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"errors"
	"math/big"
)

const (
	msgTypeData      = byte(3)
	msgTypeDHCommit  = byte(2)
	msgTypeDHKey     = byte(10)
	msgTypeRevealSig = byte(17)
	msgTypeSig       = byte(18)
)

type message interface {
	serialize() []byte
	deserialize(msg []byte) error
}

type messageHeader struct {
	protocolVersion     uint16
	needInstanceTag     bool
	senderInstanceTag   uint32
	receiverInstanceTag uint32
}

type dhCommit struct {
	messageHeader
	gx          *big.Int
	encryptedGx []byte
	hashedGx    [sha256.Size]byte
}

func (c dhCommit) serialize() []byte {
	out := appendShort(nil, c.protocolVersion)
	out = append(out, msgTypeDHCommit)
	if c.needInstanceTag {
		out = appendWord(out, c.senderInstanceTag)
		out = appendWord(out, c.receiverInstanceTag)
	}
	out = appendData(out, c.encryptedGx)
	if c.hashedGx == [sha256.Size]byte{} {
		c.hashedGx = sha256.Sum256(appendMPI(nil, c.gx))
	}
	out = appendData(out, c.hashedGx[:])

	return out
}

func (c *dhCommit) deserialize(msg []byte) error {
	var ok1 bool
	msg, c.encryptedGx, ok1 = extractData(msg)
	_, h, ok2 := extractData(msg)
	if !ok1 || !ok2 {
		return errors.New("otr: corrupt DH commit message")
	}
	copy(c.hashedGx[:], h)
	return nil
}

type dhKey struct {
	messageHeader
	gy *big.Int
}

func (c dhKey) serialize() []byte {
	out := appendShort(nil, c.protocolVersion)
	out = append(out, msgTypeDHKey)
	if c.needInstanceTag {
		out = appendWord(out, c.senderInstanceTag)
		out = appendWord(out, c.receiverInstanceTag)
	}

	return appendMPI(out, c.gy)
}

func (c *dhKey) deserialize(msg []byte) error {
	_, gy, ok := extractMPI(msg)

	if !ok {
		return errors.New("otr: corrupt DH key message")
	}

	// TODO: is this only for otrv3 or for v2 too?
	if lt(gy, g1) || gt(gy, pMinusTwo) {
		return errors.New("otr: DH value out of range")
	}

	c.gy = gy
	return nil
}

type revealSig struct {
	messageHeader
	r            [16]byte
	encryptedSig []byte
	macSig       []byte
}

func (c revealSig) serialize() []byte {
	out := appendShort(nil, c.protocolVersion)
	out = append(out, msgTypeRevealSig)
	if c.needInstanceTag {
		out = appendWord(out, c.senderInstanceTag)
		out = appendWord(out, c.receiverInstanceTag)
	}
	out = appendData(out, c.r[:])
	out = append(out, c.encryptedSig...)
	return append(out, c.macSig[:20]...)
}

func (c *revealSig) deserialize(msg []byte) error {
	in, r, ok1 := extractData(msg)
	macSig, encryptedSig, ok2 := extractData(in)
	if !ok1 || !ok2 || len(macSig) != 20 {
		return errors.New("otr: corrupt reveal signature message")
	}

	copy(c.r[:], r)
	c.encryptedSig = encryptedSig
	c.macSig = macSig
	return nil
}

type sig struct {
	messageHeader
	encryptedSig []byte
	macSig       []byte
}

func (c sig) serialize() []byte {
	out := appendShort(nil, c.protocolVersion)
	out = append(out, msgTypeSig)
	if c.needInstanceTag {
		out = appendWord(out, c.senderInstanceTag)
		out = appendWord(out, c.receiverInstanceTag)
	}
	out = append(out, c.encryptedSig...)
	return append(out, c.macSig[:20]...)
}

func (c *sig) deserialize(msg []byte) error {
	macSig, encryptedSig, ok := extractData(msg)

	if !ok || len(macSig) != 20 {
		return errors.New("otr: corrupt signature message")
	}
	c.encryptedSig = encryptedSig
	c.macSig = macSig
	return nil
}

type dataMsg struct {
	messageHeader
	flag                        byte
	senderKeyID, recipientKeyID uint32
	y                           *big.Int
	topHalfCtr                  [8]byte
	encryptedMsg                []byte
	macKey                      macKey
	authenticator               [20]byte
	oldMACKeys                  []macKey
}

func (c *dataMsg) sign() *dataMsg {
	mac := hmac.New(sha1.New, c.macKey[:])
	mac.Write(c.serializeUnsigned())
	copy(c.authenticator[:], mac.Sum(nil))
	return c
}

func (c dataMsg) serializeUnsigned() []byte {
	var out []byte

	out = appendShort(out, c.protocolVersion)
	out = append(out, msgTypeData)

	if c.needInstanceTag {
		out = appendWord(out, c.senderInstanceTag)
		out = appendWord(out, c.receiverInstanceTag)
	}
	//TODO: implement IGNORE_UNREADABLE
	out = append(out, c.flag)
	out = appendWord(out, c.senderKeyID)
	out = appendWord(out, c.recipientKeyID)
	out = appendMPI(out, c.y)
	out = append(out, c.topHalfCtr[:]...)
	out = appendData(out, c.encryptedMsg)
	return out
}

func (c dataMsg) serialize() []byte {
	out := c.serializeUnsigned()
	c.sign()
	/*
		mac := hmac.New(sha1.New, c.macKey[:])
		mac.Write(out)
		out = mac.Sum(out)
	*/
	out = append(out, c.authenticator[:]...)

	keyLen := len(macKey{})
	revKeys := make([]byte, 0, len(c.oldMACKeys)*keyLen)
	for _, k := range c.oldMACKeys {
		revKeys = append(revKeys, k[:]...)
	}
	out = appendData(out, revKeys)

	return out
}

func (c *dataMsg) deserialize(msg []byte) error {
	if len(msg) == 0 {
		return errors.New("otr: dataMsg.deserialize empty message")
	}
	in := msg
	c.flag = in[0]

	in = in[1:]
	var ok bool
	in, c.senderKeyID, ok = extractWord(in)
	if !ok {
		return errors.New("otr: dataMsg.deserialize corrupted senderKeyID")
	}
	in, c.recipientKeyID, ok = extractWord(in)
	if !ok {
		return errors.New("otr: dataMsg.deserialize corrupted recipientKeyID")
	}
	in, c.y, ok = extractMPI(in)
	if !ok {
		return errors.New("otr: dataMsg.deserialize corrupted y")
	}
	if len(in) < len(c.topHalfCtr) {
		return errors.New("otr: dataMsg.deserialize corrupted topHalfCtr")
	}
	copy(c.topHalfCtr[:], in)
	in = in[len(c.topHalfCtr):]
	in, c.encryptedMsg, ok = extractData(in)
	if !ok {
		return errors.New("otr: dataMsg.deserialize corrupted encryptedMsg")
	}

	//FIXME: pass macKey instead of deserialize it from dataMsg
	copy(c.macKey[:], in)
	in = in[len(c.macKey):]

	var revKeysBytes []byte
	in, revKeysBytes, ok = extractData(in)
	if !ok {
		return errors.New("otr: failed to deserialize data message")
	}
	for len(revKeysBytes) > 0 {
		var revKey [sha1.Size]byte
		if len(revKeysBytes) < sha1.Size {
			return errors.New("otr: failed to deserialize data message")
		}
		copy(revKey[:], revKeysBytes)
		c.oldMACKeys = append(c.oldMACKeys, revKey)
		revKeysBytes = revKeysBytes[len(revKey):]
	}

	return nil
}

type dataMsgPlainText struct {
	plain []byte
	tlvs  []tlv
}

func (c *dataMsgPlainText) deserialize(msg []byte) error {
	nulPos := 0
	for nulPos < len(msg) && msg[nulPos] != 0x00 {
		nulPos++
	}

	var tlvsBytes []byte
	if nulPos < len(msg) {
		c.plain = msg[:nulPos]
		tlvsBytes = msg[nulPos+1:]
	} else {
		c.plain = msg
	}

	for len(tlvsBytes) > 0 {
		atlv := tlv{}
		if err := atlv.deserialize(tlvsBytes); err != nil {
			return err
		}
		c.tlvs = append(c.tlvs, atlv)
		tlvsBytes = tlvsBytes[4+int(atlv.tlvLength):]
	}
	return nil
}

func (c dataMsgPlainText) serialize() []byte {
	out := c.plain
	out = append(out, 0x00)

	if len(c.tlvs) > 0 {
		for i := range c.tlvs {
			out = appendShort(out, c.tlvs[i].tlvType)
			out = appendShort(out, c.tlvs[i].tlvLength)
			out = append(out, c.tlvs[i].tlvValue...)
		}
	}
	return out
}

const (
	paddingGranularity = 256
	tlvHeaderLen       = 4
	nulByteLen         = 1
)

func (c dataMsgPlainText) pad() dataMsgPlainText {
	padding := paddingGranularity - ((len(c.plain) + tlvHeaderLen + nulByteLen) % paddingGranularity)

	paddingTlv := tlv{
		tlvType:   0,
		tlvLength: uint16(padding),
		tlvValue:  make([]byte, padding),
	}

	c.tlvs = append(c.tlvs, paddingTlv)

	return c
}

func (c dataMsgPlainText) encrypt(key [aes.BlockSize]byte, counter [8]byte) []byte {
	// This can not cause an error
	encrypted, _ := encrypt(key[:], c.pad().serialize())
	return encrypted
}

type tlv struct {
	tlvType   uint16
	tlvLength uint16
	tlvValue  []byte
}

func (c tlv) serialize() []byte {
	out := appendShort([]byte{}, c.tlvType)
	out = appendShort(out, c.tlvLength)
	return append(out, c.tlvValue...)
}

func (c *tlv) deserialize(tlvsBytes []byte) error {
	var ok bool
	tlvsBytes, c.tlvType, ok = extractShort(tlvsBytes)
	if !ok {
		return errors.New("otr: wrong tlv type")
	}
	tlvsBytes, c.tlvLength, ok = extractShort(tlvsBytes)
	if !ok {
		return errors.New("otr: wrong tlv length")
	}
	if len(tlvsBytes) < int(c.tlvLength) {
		return errors.New("otr: wrong tlv value")
	}
	c.tlvValue = tlvsBytes[:int(c.tlvLength)]
	return nil
}
