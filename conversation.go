package otr3

import (
	"bytes"
	"encoding/binary"
	"io"
	"math/big"
)

const (
	lenMsgHeader = 3
)

type conversation struct {
	version             otrVersion
	Rand                io.Reader
	smpState            smpState
	secret              *big.Int
	s1                  smp1State
	s2                  smp2State
	s3                  smp3State
	authState           authState
	msgState            msgState
	r                   [16]byte
	sigKey              akeKeys
	senderInstanceTag   uint32
	receiverInstanceTag uint32
	ourKey              *PrivateKey
	theirKey            *PublicKey
	revealSigMsg        []byte
	keys                keyManagementContext
	revealKey           akeKeys
	ssid                [8]byte
	policies            policies
	ake                 *ake
}

type msgState int

const (
	plainText msgState = iota
	encrypted
	finished
)

func newConversation(v otrVersion, rand io.Reader) *conversation {
	return &conversation{
		version:   v,
		Rand:      rand,
		smpState:  smpStateExpect1{},
		authState: authStateNone{},
		policies:  policies(0),
	}
}

func (c *conversation) messageHeader() messageHeader {
	return messageHeader{
		protocolVersion:     c.version.protocolVersion(),
		needInstanceTag:     c.version.needInstanceTag(),
		senderInstanceTag:   c.senderInstanceTag,
		receiverInstanceTag: c.receiverInstanceTag,
	}
}

func (c *conversation) genDataMsg(message []byte, tlvs ...tlv) dataMsg {
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
		//TODO after key management
		oldMACKeys: []macKey{},
	}

	return dataMessage
}

func (c *conversation) send(message []byte) {
	// FIXME Dummy for now
}

var queryMarker = []byte("?OTR")

func isQueryMessage(msg []byte) bool {
	return bytes.HasPrefix(msg, []byte(queryMarker))
}

// This should be used by the xmpp-client to received OTR messages in plain
//TODO toSend needs fragmentation to be implemented
func (c *conversation) receive(message []byte) (toSend []byte, err error) {
	if isQueryMessage(message) {
		toSend, err = c.receiveQueryMessage(message)
		return
	}

	// TODO check the message instanceTag for V3
	// I should ignore the message if it is not for my conversation

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

func (c *conversation) processDataMessage(msg []byte) []byte {
	msg = msg[c.version.headerLen():]
	dataMessage := dataMsg{}
	dataMessage.deserialize(msg)

	return []byte{}
}
