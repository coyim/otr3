package otr3

import (
	"bytes"
	"encoding/base64"
)

func (c *Conversation) receiveWithoutOTR(message []byte) (plain []byte, toSend [][]byte, err error) {
	return message, nil, nil
}

func (c *Conversation) receiveErrorMessage(message []byte) (plain []byte, toSend [][]byte, err error) {
	plain = message[len(errorMarker):]

	if c.policies.has(errorStartAKE) {
		toSend = [][]byte{c.queryMessage()}
	}

	return
}

func (c *Conversation) toSendEncoded2(toSend []byte, err error) ([]byte, [][]byte, error) {
	if err != nil {
		return nil, nil, err
	}
	return nil, c.encode(toSend), err
}

func (c *Conversation) toSendEncoded3(plain, toSend []byte, err error) ([]byte, [][]byte, error) {
	if err != nil || len(toSend) == 0 {
		return plain, nil, err
	}
	return plain, c.encode(toSend), err
}

func (c *Conversation) receiveEncoded(message []byte) ([]byte, []byte, error) {
	decodedMessage, err := c.decode(message)
	if err != nil {
		return nil, nil, err
	}
	return c.receiveDecoded(decodedMessage)
}

func (c *Conversation) receiveOther(message []byte) ([]byte, []byte, error) {
	c.whitespaceTagIgnored = c.policies.has(sendWhitespaceTag)

	//TODO:	warn that the message was received unencrypted
	if c.msgState != plainText || c.policies.has(requireEncryption) {
		//FIXME: returning an error might not be the best semantic to "it worked,
		//but we have to notify you that something unexpected happened"
		//err = errUnexpectedPlainMessage
	}

	return c.processWhitespaceTag(message)
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

func (c *Conversation) receiveDecoded(message []byte) (plain, toSend []byte, err error) {
	if err = c.checkVersion(message); err != nil {
		return
	}

	var messageBody []byte
	if messageBody, err = c.parseMessageHeader(message); err != nil {
		return
	}

	msgType := message[2]
	if msgType == msgTypeData {
		if c.msgState != encrypted {
			toSend = c.restart()
			err = errEncryptedMessageWithNoSecureChannel
			return
		}

		plain, toSend, err = c.processDataMessage(messageBody)
	} else {
		toSend, err = c.receiveAKE(msgType, messageBody)
	}

	return
}

func isEncoded(msg []byte) bool {
	return bytes.HasPrefix(msg, msgMarker) && msg[len(msg)-1] == '.'
}

func isErrorMessage(msg []byte) bool {
	return bytes.HasPrefix(msg, errorMarker)
}

func (c *Conversation) Receive(message []byte) (plain []byte, toSend [][]byte, err error) {
	switch {
	case !c.policies.isOTREnabled():
		return c.receiveWithoutOTR(message)
	case isErrorMessage(message):
		return c.receiveErrorMessage(message)
	case isEncoded(message):
		return c.toSendEncoded3(c.receiveEncoded(message))
	case isQueryMessage(message):
		return c.toSendEncoded2(c.receiveQueryMessage(message))
	default:
		return c.toSendEncoded3(c.receiveOther(message))
	}
}
