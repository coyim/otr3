package otr3

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"io"
)

const ()

type Conversation struct {
	//TODO:xmpp is using TheirPublicKey
	//TheirPublicKey PublicKey
	//TODO:xmpp is using PrivateKey
	//PrivateKey PrivateKey
	//TODO:xmpp is using SSID
	//SSID    [8]byte
	//TODO:move FragmentSize to compat pack
	FragmentSize int

	version otrVersion
	Rand    io.Reader

	msgState msgState

	ourInstanceTag   uint32
	theirInstanceTag uint32

	ourKey   *PrivateKey
	theirKey *PublicKey

	keys keyManagementContext

	ssid     [8]byte
	policies policies
	ake      *ake
	smp      smp
}

type msgState int

const (
	plainText msgState = iota
	encrypted
	finished
)

//TODO: is these const necessary?
var (
	msgPrefix       = []byte("?OTR:")
	queryMarker     = []byte("?OTR")
	minFragmentSize = 18
)

//NOTE: this should be only used in tests
func newConversation(v otrVersion, rand io.Reader) *Conversation {
	var p policy
	switch v {
	case otrV3{}:
		p = allowV3
	case otrV2{}:
		p = allowV2
	}

	return &Conversation{
		version: v,
		Rand:    rand,
		smp: smp{
			state: smpStateExpect1{},
		},
		policies: policies(p),
	}
}

func (c *Conversation) genDataMsg(message []byte, tlvs ...tlv) dataMsg {
	keys, err := c.keys.calculateDHSessionKeys(c.keys.ourKeyID-1, c.keys.theirKeyID)
	if err != nil {
		//TODO errors
		return dataMsg{}
	}

	topHalfCtr := [8]byte{}
	binary.BigEndian.PutUint64(topHalfCtr[:], c.keys.ourCounter)
	c.keys.ourCounter++

	plain := dataMsgPlainText{
		plain: message,
		tlvs:  tlvs,
	}

	encrypted := plain.encrypt(keys.sendingAESKey, topHalfCtr)
	dataMessage := dataMsg{
		//TODO: implement IGNORE_UNREADABLE
		flag: 0x00,

		senderKeyID:    c.keys.ourKeyID - 1,
		recipientKeyID: c.keys.theirKeyID,
		y:              c.keys.ourCurrentDHKeys.pub,
		topHalfCtr:     topHalfCtr,
		encryptedMsg:   encrypted,
		oldMACKeys:     c.keys.revealMACKeys(),
	}
	dataMessage.sign(keys.sendingMACKey)

	return dataMessage
}

func (c *Conversation) Send(message []byte) []byte {
	// FIXME Dummy for now
	var ret []byte

	if !c.policies.isOTREnabled() {
		return message
	}

	ret = c.appendWhitespaceTag(message)

	return ret
}

func isQueryMessage(msg []byte) bool {
	return bytes.HasPrefix(msg, []byte(queryMarker))
}

// This should be used by the xmpp-client to received OTR messages in plain
//TODO toSend needs fragmentation to be implemented
func (c *Conversation) Receive(message []byte) (toSend []byte, err error) {
	if !c.policies.isOTREnabled() {
		return
	}

	//TODO: warn the user for REQUIRE_ENCRYPTION
	//See: Receiving plaintext with/without the whitespace tag

	if isQueryMessage(message) {
		toSend, err = c.receiveQueryMessage(message)
		return
	}

	message, toSend, err = c.processWhitespaceTag(message)
	if err != nil || toSend != nil {
		return
	}

	// TODO check the message instanceTag for V3
	// I should ignore the message if it is not for my Conversation

	_, msgProtocolVersion, ok := extractShort(message)
	if !ok {
		return nil, errInvalidOTRMessage
	}

	msgType := message[2]
	if msgType != msgTypeDHCommit && c.version.protocolVersion() != msgProtocolVersion {
		return nil, errWrongProtocolVersion
	}

	switch msgType {
	case msgTypeData:
		if c.msgState != encrypted {
			return c.restart(), errEncryptedMessageWithNoSecureChannel
		}

		//TODO: return plain
		_, toSend, err = c.processDataMessage(message)
		if err != nil {
			return
		}

	default:
		return c.receiveAKE(message)
	}

	return
}

func (c *Conversation) processTLVs(tlvs []tlv) ([]byte, error) {
	var toSend []byte
	var err error

	for _, tlv := range tlvs {
		//FIXME: ignore non SMP messages for now
		if tlv.tlvType == 0x00 {
			continue
		}

		//FIXME: dont need to serialize again
		//Change parseTLV to convert tlv objects to smpMessages
		smpMessage, ok := parseTLV(tlv.serialize())
		if !ok {
			return nil, newOtrError("corrupt data message")
		}

		//FIXME: What if it receives multiple SMP messages in the same data message?
		//FIXME: toSend should be a DATA message. It is a TLV serialized
		toSend, err = c.receiveSMP(smpMessage)
		if err != nil {
			return nil, err
		}
	}

	return toSend, err
}

func (c *Conversation) processDataMessage(msg []byte) (plain, toSend []byte, err error) {
	// FIXME: deal with errors in this function
	msg, _ = c.parseMessageHeader(msg)

	dataMessage := dataMsg{}

	err = dataMessage.deserialize(msg)
	if err != nil {
		return
	}

	sessionKeys, err := c.keys.calculateDHSessionKeys(dataMessage.recipientKeyID, dataMessage.senderKeyID)
	if err != nil {
		return
	}

	if err = dataMessage.checkSign(sessionKeys.receivingMACKey); err != nil {
		return
	}

	p := dataMsgPlainText{}
	err = p.decrypt(sessionKeys.receivingAESKey, dataMessage.topHalfCtr, dataMessage.encryptedMsg)
	if err != nil {
		return
	}

	plain = p.plain
	toSend, err = c.processTLVs(p.tlvs)
	if err != nil {
		return
	}

	return
}

func (c *Conversation) messageHeader(msgType byte) []byte {
	return c.version.messageHeader(c, msgType)
}

func (c *Conversation) parseMessageHeader(msg []byte) ([]byte, error) {
	return c.version.parseMessageHeader(c, msg)
}

func (c *Conversation) IsEncrypted() bool {
	return c.msgState == encrypted
}

func (c *Conversation) encode(msg []byte) [][]byte {
	b64 := make([]byte, base64.StdEncoding.EncodedLen(len(msg))+len(msgPrefix)+1)
	base64.StdEncoding.Encode(b64[len(msgPrefix):], msg)
	copy(b64, msgPrefix)
	b64[len(b64)-1] = '.'

	if c.FragmentSize < minFragmentSize || len(b64) <= c.FragmentSize {
		// We can encode this in a single fragment.
		return [][]byte{b64}
	}

	bytesPerFragment := c.FragmentSize - minFragmentSize
	//TODO: need implementation of InstanceTag ready
	return c.fragment(b64, uint16(bytesPerFragment), uint32(0), uint32(0))
}

func (c *Conversation) End() (toSend [][]byte) {
	switch c.msgState {
	case plainText:
		return nil
	case encrypted:
		c.msgState = plainText
		return c.encode(c.genDataMsg(nil, tlv{tlvType: tlvTypeDisconnected}).serialize(c))
	case finished:
		c.msgState = plainText
		return nil
	}
	//FIXME: old implementation has panic("unreachable")
	return nil
}

/*TODO: Authenticate
func (c *Conversation) Authenticate(question string, mutualSecret []byte) (toSend [][]byte, err error) {
	return [][]byte{}, nil
}
*/
/*TODO: SMPQuestion
func (c *Conversation) SMPQuestion() string {
	return c.smp.question
}
*/
