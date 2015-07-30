package otr3

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"io"
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

	ssid         [8]byte
	policies     policies
	ake          *ake
	smp          smp
	fragmentSize uint16
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

func (c *Conversation) genDataMsg(message []byte, tlvs ...tlv) dataMsg {
	keys, err := c.keys.calculateDHSessionKeys(c.keys.ourKeyID-1, c.keys.theirKeyID)
	if err != nil {
		//TODO errors
		return dataMsg{}
	}

	topHalfCtr := [8]byte{}
	binary.BigEndian.PutUint64(topHalfCtr[:], c.keys.ourCounter)
	c.keys.ourCounter++

	plain := plainDataMsg{
		message: message,
		tlvs:    tlvs,
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

func (c *Conversation) Send(msg []byte) ([][]byte, error) {
	if !c.policies.isOTREnabled() {
		return [][]byte{msg}, nil
	}
	switch c.msgState {
	case plainText:
		if c.policies.has(requireEncryption) {
			return [][]byte{[]byte(c.queryMessage())}, nil
		}
		if c.policies.has(sendWhitespaceTag) {
			msg = c.appendWhitespaceTag(msg)
		}
		return [][]byte{msg}, nil
	case encrypted:
		return c.encode(c.genDataMsg(msg).serialize(c)), nil
	case finished:
		return nil, errors.New("otr: cannot send message because secure conversation has finished")
	}

	return nil, errors.New("otr: cannot send message in current state")
}

func (c Conversation) queryMessage() string {
	queryMessage := "?OTRv"
	if c.policies.has(allowV2) {
		queryMessage += "2"
	}
	if c.policies.has(allowV3) {
		queryMessage += "3"
	}
	return queryMessage + "?"
}

func isQueryMessage(msg []byte) bool {
	return bytes.HasPrefix(msg, []byte(queryMarker))
}

// This should be used by the xmpp-client to received OTR messages in plain
//TODO For the exported Receive, toSend needs fragmentation, base64 encoding
func (c *Conversation) Receive(message []byte) (plain, toSend []byte, err error) {
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
		err = errInvalidOTRMessage
		return
	}

	msgType := message[2]
	if msgType != msgTypeDHCommit && c.version.protocolVersion() != msgProtocolVersion {
		err = errWrongProtocolVersion
		return
	}

	switch msgType {
	case msgTypeData:
		if c.msgState != encrypted {
			toSend = c.restart()
			err = errEncryptedMessageWithNoSecureChannel
			return
		}

		plain, toSend, err = c.processDataMessage(message)
		if err != nil {
			return
		}

	default:
		toSend, err = c.receiveAKE(message)
	}

	return
}

func (c *Conversation) processTLVs(tlvs []tlv) ([]tlv, error) {
	var retTLVs []tlv
	var err error

	for _, tlv := range tlvs {
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
		tlv, err = c.receiveSMP(smpMessage)
		if err != nil {
			return nil, err
		}

		retTLVs = append(retTLVs, tlv)
	}

	return retTLVs, err
}

func (c *Conversation) rotateKeys(dataMessage dataMsg) error {
	c.keys.rotateTheirKey(dataMessage.senderKeyID, dataMessage.y)

	x, ok := c.randMPI(make([]byte, 40))
	if !ok {
		//NOTE: what should we do?
		//This is one kind of error that breaks the encrypted channel. I believe we
		//should change the msgState to != encrypted
		return errShortRandomRead
	}

	c.keys.rotateOurKeys(dataMessage.recipientKeyID, x)

	return nil
}

func (c *Conversation) processDataMessage(msg []byte) (plain, toSend []byte, err error) {
	// FIXME: deal with errors in this function
	msg, _ = c.parseMessageHeader(msg)

	dataMessage := dataMsg{}

	err = dataMessage.deserialize(msg)
	if err != nil {
		return
	}

	//TODO: Check that the counter in the Data message is strictly larger than the last counter you saw using this pair of keys. If not, reject the message.

	sessionKeys, err := c.keys.calculateDHSessionKeys(dataMessage.recipientKeyID, dataMessage.senderKeyID)
	if err != nil {
		return
	}

	if err = dataMessage.checkSign(sessionKeys.receivingMACKey); err != nil {
		return
	}

	p := plainDataMsg{}
	err = p.decrypt(sessionKeys.receivingAESKey, dataMessage.topHalfCtr, dataMessage.encryptedMsg)
	if err != nil {
		return
	}

	plain = p.message
	err = c.rotateKeys(dataMessage)
	if err != nil {
		return
	}

	//TODO: TEST. Should not process TLVs if it fails to rotate keys. This is how
	//libotr does
	var tlvs []tlv
	tlvs, err = c.processTLVs(p.tlvs)
	if err != nil {
		return
	}

	if len(tlvs) > 0 {
		toSend = c.genDataMsg(nil, tlvs...).serialize(c)
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

	bytesPerFragment := c.fragmentSize - c.version.minFragmentSize()
	return c.fragment(b64, bytesPerFragment, uint32(0), uint32(0))
}

func (c *Conversation) End() (toSend [][]byte, ok bool) {
	ok = true
	switch c.msgState {
	case plainText:
	case encrypted:
		c.msgState = plainText
		toSend = c.encode(c.genDataMsg(nil, tlv{tlvType: tlvTypeDisconnected}).serialize(c))
	case finished:
		c.msgState = plainText
	}
	ok = false
	return
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
