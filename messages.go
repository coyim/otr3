package otr3

import (
	"crypto/aes"
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"math/big"
)

const messageFlagNormal = byte(0x00)
const messageFlagIgnoreUnreadable = byte(0x01)

const messageHeaderPrefix = 3

const (
	msgTypeDHCommit  = byte(0x02)
	msgTypeData      = byte(0x03)
	msgTypeDHKey     = byte(0x0A)
	msgTypeRevealSig = byte(0x11)
	msgTypeSig       = byte(0x12)
)

type message interface {
	serialize() []byte
	deserialize(msg []byte) error
}

type dhCommit struct {
	gx          *big.Int
	encryptedGx []byte
	hashedGx    [sha256.Size]byte
}

func (c dhCommit) serialize() []byte {
	var out []byte
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
		return newOtrError("corrupt DH commit message")
	}
	copy(c.hashedGx[:], h)
	return nil
}

type dhKey struct {
	gy *big.Int
}

func (c dhKey) serialize() []byte {
	var out []byte
	return appendMPI(out, c.gy)
}

func (c *dhKey) deserialize(msg []byte) error {
	_, gy, ok := extractMPI(msg)

	if !ok {
		return newOtrError("corrupt DH key message")
	}

	if lt(gy, g1) || gt(gy, pMinusTwo) {
		return newOtrError("DH value out of range")
	}

	c.gy = gy
	return nil
}

type revealSig struct {
	r            [16]byte
	encryptedSig []byte
	macSig       []byte
}

func (c revealSig) serialize() []byte {
	var out []byte
	out = appendData(out, c.r[:])
	out = append(out, c.encryptedSig...)
	return append(out, c.macSig[:20]...)
}

func (c *revealSig) deserialize(msg []byte) error {
	in, r, ok1 := extractData(msg)
	macSig, encryptedSig, ok2 := extractData(in)
	if !ok1 || !ok2 || len(macSig) != 20 {
		return newOtrError("corrupt reveal signature message")
	}

	copy(c.r[:], r)
	c.encryptedSig = encryptedSig
	c.macSig = macSig
	return nil
}

type sig struct {
	encryptedSig []byte
	macSig       []byte
}

func (c sig) serialize() []byte {
	var out []byte
	out = append(out, c.encryptedSig...)
	return append(out, c.macSig[:20]...)
}

func (c *sig) deserialize(msg []byte) error {
	macSig, encryptedSig, ok := extractData(msg)

	if !ok || len(macSig) != 20 {
		return newOtrError("corrupt signature message")
	}
	c.encryptedSig = encryptedSig
	c.macSig = macSig
	return nil
}

type dataMsg struct {
	flag                        byte
	senderKeyID, recipientKeyID uint32
	y                           *big.Int
	topHalfCtr                  [8]byte
	encryptedMsg                []byte
	authenticator               [20]byte
	oldMACKeys                  []macKey
	serializeUnsignedCache      []byte
}

func (c *dataMsg) sign(key macKey, header []byte) {
	if c.serializeUnsignedCache == nil {
		c.serializeUnsignedCache = c.serializeUnsigned()
	}
	mac := hmac.New(sha1.New, key[:])
	mac.Write(header)
	mac.Write(c.serializeUnsignedCache)
	copy(c.authenticator[:], mac.Sum(nil))
}

func (c dataMsg) checkSign(key macKey, header []byte) error {
	var authenticatorCalculated [20]byte
	mac := hmac.New(sha1.New, key[:])
	mac.Write(header)
	mac.Write(c.serializeUnsignedCache)
	copy(authenticatorCalculated[:], mac.Sum(nil))

	if subtle.ConstantTimeCompare(c.authenticator[:], authenticatorCalculated[:]) == 0 {
		return ErrGPGConflict
	}
	return nil
}

func (c dataMsg) serializeUnsigned() []byte {
	var out []byte

	out = append(out, c.flag)
	out = appendWord(out, c.senderKeyID)
	out = appendWord(out, c.recipientKeyID)
	out = appendMPI(out, c.y)
	out = append(out, c.topHalfCtr[:]...)
	out = appendData(out, c.encryptedMsg)
	return out
}

func (c *dataMsg) deserializeUnsigned(msg []byte) error {
	if len(msg) == 0 {
		return newOtrError("dataMsg.deserialize empty message")
	}
	in := msg
	c.flag = in[0]

	in = in[1:]
	var ok bool

	in, c.senderKeyID, ok = extractWord(in)
	if !ok {
		return newOtrError("dataMsg.deserialize corrupted senderKeyID")
	}

	in, c.recipientKeyID, ok = extractWord(in)
	if !ok {
		return newOtrError("dataMsg.deserialize corrupted recipientKeyID")
	}

	in, c.y, ok = extractMPI(in)
	if !ok {
		return newOtrError("dataMsg.deserialize corrupted y")
	}

	if len(in) < len(c.topHalfCtr) {
		return newOtrError("dataMsg.deserialize corrupted topHalfCtr")
	}

	if binary.BigEndian.Uint64(in) == 0 {
		return newOtrError("dataMsg.deserialize invalid topHalfCtr")
	}

	copy(c.topHalfCtr[:], in)
	in = in[len(c.topHalfCtr):]
	in, c.encryptedMsg, ok = extractData(in)
	if !ok {
		return newOtrError("dataMsg.deserialize corrupted encryptedMsg")
	}

	c.serializeUnsignedCache = msg[:len(msg)-len(in)]
	return nil
}

func (c dataMsg) serialize() []byte {
	if c.serializeUnsignedCache == nil {
		c.serializeUnsignedCache = c.serializeUnsigned()
	}

	out := append([]byte{}, c.serializeUnsignedCache...)
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
	if err := c.deserializeUnsigned(msg); err != nil {
		return err
	}

	msg = msg[len(c.serializeUnsignedCache):]
	copy(c.authenticator[:], msg)
	msg = msg[len(c.authenticator):]

	var revKeysBytes []byte
	msg, revKeysBytes, ok := extractData(msg)
	if !ok {
		return newOtrError("dataMsg.deserialize corrupted revealMACKeys")
	}
	for len(revKeysBytes) > 0 {
		var revKey macKey
		if len(revKeysBytes) < sha1.Size {
			return newOtrError("dataMsg.deserialize corrupted revealMACKeys")
		}
		copy(revKey[:], revKeysBytes)
		c.oldMACKeys = append(c.oldMACKeys, revKey)
		revKeysBytes = revKeysBytes[len(revKey):]
	}

	return nil
}

type plainDataMsg struct {
	message []byte
	tlvs    []tlv
}

func (c *plainDataMsg) deserialize(msg []byte) error {
	nulPos := 0
	for nulPos < len(msg) && msg[nulPos] != 0x00 {
		nulPos++
	}

	var tlvsBytes []byte
	if nulPos < len(msg) {
		c.message = msg[:nulPos]
		tlvsBytes = msg[nulPos+1:]
	} else {
		c.message = msg
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

func (c plainDataMsg) serialize() []byte {
	out := c.message
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

func (c plainDataMsg) pad() plainDataMsg {
	padding := paddingGranularity - ((len(c.message) + tlvHeaderLen + nulByteLen) % paddingGranularity)

	paddingTlv := tlv{
		tlvType:   uint16(tlvTypePadding),
		tlvLength: uint16(padding),
		tlvValue:  make([]byte, padding),
	}

	c.tlvs = append(c.tlvs, paddingTlv)

	return c
}

func (c plainDataMsg) encrypt(key [aes.BlockSize]byte, topHalfCtr [8]byte) []byte {
	var iv [aes.BlockSize]byte
	copy(iv[:], topHalfCtr[:])

	data := c.pad().serialize()
	dst := make([]byte, len(data))
	counterEncipher(key[:], iv[:], data, dst)
	return dst
}

func (c *plainDataMsg) decrypt(key [aes.BlockSize]byte, topHalfCtr [8]byte, src []byte) error {
	var iv [aes.BlockSize]byte
	copy(iv[:], topHalfCtr[:])

	if err := counterEncipher(key[:], iv[:], src, src); err != nil {
		return err
	}

	c.deserialize(src)
	return nil
}
