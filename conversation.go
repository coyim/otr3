package otr3

import (
	"bytes"
	"encoding/binary"
	"io"
)

const (
	lenMsgHeader = 3
)

type Conversation struct {
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

func (c *Conversation) messageHeader() messageHeader {
	return messageHeader{
		protocolVersion:     c.version.protocolVersion(),
		needInstanceTag:     c.version.needInstanceTag(),
		senderInstanceTag:   c.ourInstanceTag,
		receiverInstanceTag: c.theirInstanceTag,
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
	msgHeader := c.messageHeader()
	dataMessage := dataMsg{
		messageHeader: msgHeader,
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

func (c *Conversation) appendWhitespaceTag(message []byte) []byte {
	if !c.policies.has(sendWhitespaceTag) {
		return message
	}

	return append(message, genWhitespaceTag(c.policies)...)
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

var queryMarker = []byte("?OTR")

func isQueryMessage(msg []byte) bool {
	return bytes.HasPrefix(msg, []byte(queryMarker))
}

// This should be used by the xmpp-client to received OTR messages in plain
//TODO toSend needs fragmentation to be implemented
func (c *Conversation) Receive(message []byte) (toSend []byte, err error) {
	if !c.policies.isOTREnabled() {
		return
	}

	if isQueryMessage(message) {
		toSend, err = c.receiveQueryMessage(message)
		return
	}

	// TODO check the message instanceTag for V3
	// I should ignore the message if it is not for my Conversation

	_, msgProtocolVersion, ok := extractShort(message)
	if !ok {
		return nil, errInvalidOTRMessage
	}

	if c.version.protocolVersion() != msgProtocolVersion {
		return nil, errWrongProtocolVersion
	}

	switch message[2] {
	case msgTypeData:
		if c.msgState != encrypted {
			return c.restart(), errEncryptedMessageWithNoSecureChannel
		}

		//TODO: c.processDataMessage(message)
		//TODO: decrypt data from data message and extract TLVs from it
		tlv := message
		smpMessage, ok := parseTLV(tlv)
		if !ok {
			return nil, newOtrError("corrupt data message")
		}

		//TODO: rotate their key
		//c.rotateTheirKey(msg.senderKeyID, msg.y)

		//TODO: encrypt toSend and wrap in a DATA message
		c.receiveSMP(smpMessage)
	default:
		return c.receiveAKE(message)
	}

	return
}

func (c *Conversation) processDataMessage(msg []byte) ([]byte, []tlv, error) {
	msg = msg[c.version.headerLen():]
	dataMessage := dataMsg{}
	dataMessage.deserialize(msg)
	sessionKeys, err := c.keys.calculateDHSessionKeys(dataMessage.recipientKeyID, dataMessage.senderKeyID)
	if err != nil {
		return nil, nil, err
	}
	if err := dataMessage.checkSign(sessionKeys.receivingMACKey); err != nil {
		return nil, nil, err
	}
	plain := dataMsgPlainText{}
	err = plain.decrypt(sessionKeys.receivingAESKey, dataMessage.topHalfCtr, dataMessage.encryptedMsg)

	return plain.plain, plain.tlvs, err
}

/*TODO: IsEncrypted
func (c *Conversation) IsEncrypted() bool {
	return true
}
*/
/*TODO: End
func (c *Conversation) End() (toSend [][]byte) {
	return [][]byte{}
}
*/
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
