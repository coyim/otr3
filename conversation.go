package otr3

import (
	"bytes"
	"encoding/base64"
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

var (
	queryMarker = []byte("?OTR")
	errorMarker = []byte("?OTR Error:")
	msgMarker   = []byte("?OTR:")
)

func (c *Conversation) Send(msg []byte) ([][]byte, error) {
	if !c.policies.isOTREnabled() {
		return [][]byte{msg}, nil
	}
	switch c.msgState {
	case plainText:
		if c.policies.has(requireEncryption) {
			return [][]byte{c.queryMessage()}, nil
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

func isEncoded(msg []byte) bool {
	return bytes.HasPrefix(msg, msgMarker) && msg[len(msg)-1] == '.'
}

func isErrorMessage(msg []byte) bool {
	return bytes.HasPrefix(msg, errorMarker)
}

func (c *Conversation) receiveErrorMessage(message []byte) (plain []byte, toSend [][]byte) {
	plain = message[len(errorMarker):]

	if c.policies.has(errorStartAKE) {
		toSend = [][]byte{c.queryMessage()}
	}

	return
}

func removeOTRMsgEnvelope(msg []byte) []byte {
	return msg[len(msgMarker) : len(msg)-1]
}

func (c *Conversation) decode(encoded []byte) ([]byte, error) {
	encoded = removeOTRMsgEnvelope(encoded)
	msg := make([]byte, base64.StdEncoding.DecodedLen(len(encoded)))
	msgLen, err := base64.StdEncoding.Decode(msg, encoded)

	if err != nil {
		return nil, errInvalidOTRMessage
	}

	return msg[:msgLen], nil
}

func (c *Conversation) Receive(message []byte) (plain []byte, toSend [][]byte, err error) {
	var unencodedReturn []byte

	//TODO: warn the user for REQUIRE_ENCRYPTION
	//See: Receiving plaintext with/without the whitespace tag

	switch {
	case !c.policies.isOTREnabled():
		plain = message
		return
	case isErrorMessage(message):
		plain, toSend = c.receiveErrorMessage(message)
		return
	case isEncoded(message):
		message, err = c.decode(message)
		if err != nil {
			return
		}
		plain, unencodedReturn, err = c.receiveDecoded(message)
	case isQueryMessage(message):
		unencodedReturn, err = c.receiveQueryMessage(message)
	default:
		plain, unencodedReturn, err = c.processWhitespaceTag(message)
		if unencodedReturn == nil {
			return
		}

		//TODO:	warn that the message was received unencrypted
		if c.msgState != plainText || c.policies.has(requireEncryption) {
			//FIXME: returning an error might not be the best semantic to "it worked,
			//but we have to notify you that something unexpected happened"
			//err = errUnexpectedPlainMessage
		}
	}

	if err != nil {
		return
	}

	toSend = c.encode(unencodedReturn)
	return
}

func (c *Conversation) receiveDecoded(message []byte) (plain, toSend []byte, err error) {
	if err = c.checkVersion(message); err != nil {
		return
	}

	var messageBody []byte
	if messageBody, err = c.parseMessageHeader(message); err != nil {
		return
	}

	msgType := message[2]
	switch msgType {
	case msgTypeData:
		if c.msgState != encrypted {
			toSend = c.restart()
			err = errEncryptedMessageWithNoSecureChannel
			return
		}

		plain, toSend, err = c.processDataMessage(messageBody)
		if err != nil {
			return
		}

	default:
		toSend, err = c.receiveAKE(msgType, messageBody)
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

func (c *Conversation) encode(msg []byte) [][]byte {
	msgPrefix := []byte("?OTR:")
	b64 := make([]byte, base64.StdEncoding.EncodedLen(len(msg))+len(msgPrefix)+1)
	base64.StdEncoding.Encode(b64[len(msgPrefix):], msg)
	copy(b64, msgPrefix)
	b64[len(b64)-1] = '.'

	bytesPerFragment := c.fragmentSize - c.version.minFragmentSize()
	return c.fragment(b64, bytesPerFragment, uint32(0), uint32(0))
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
