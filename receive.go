package otr3

import "encoding/base64"

func (c *Conversation) receiveWithoutOTR(message ValidMessage) (MessagePlaintext, []ValidMessage, error) {
	return MessagePlaintext(message), nil, nil
}

func (c *Conversation) receiveErrorMessage(message ValidMessage) (plain MessagePlaintext, toSend []ValidMessage, err error) {
	plain = MessagePlaintext(message[len(errorMarker):])

	if c.Policies.has(errorStartAKE) {
		toSend = []ValidMessage{c.queryMessage()}
	}

	return
}

func (c *Conversation) toSendEncoded2(toSend messageWithHeader, err error) (MessagePlaintext, []ValidMessage, error) {
	if err != nil {
		return nil, nil, err
	}
	return nil, c.encode(toSend), err
}

func (c *Conversation) toSendEncoded3(plain MessagePlaintext, toSend messageWithHeader, err error) (MessagePlaintext, []ValidMessage, error) {
	if err != nil || len(toSend) == 0 {
		return plain, nil, err
	}

	return plain, c.encode(toSend), err
}

func (c *Conversation) toSendEncoded34(plain MessagePlaintext, toSend messageWithHeader, toSendExtra messageWithHeader, err error) (MessagePlaintext, []ValidMessage, error) {
	if err != nil || len(toSend) == 0 {
		return plain, nil, err
	}

	return plain, append(c.encode(toSend), c.encode(toSendExtra)...), err
}

func (c *Conversation) receiveEncoded(message encodedMessage) (MessagePlaintext, messageWithHeader, messageWithHeader, error) {
	decodedMessage, err := c.decode(message)
	if err != nil {
		return nil, nil, nil, err
	}
	return c.receiveDecoded(decodedMessage)
}

func (c *Conversation) receivePlaintext(message ValidMessage) (plain MessagePlaintext, toSend messageWithHeader, err error) {
	c.stopSendingWhitespaceTags = c.Policies.has(sendWhitespaceTag)

	//TODO:	warn that the message was received unencrypted

	return MessagePlaintext(message), nil, nil
}

func (c *Conversation) receiveTaggedPlaintext(message ValidMessage) (plain MessagePlaintext, toSend messageWithHeader, err error) {
	c.stopSendingWhitespaceTags = c.Policies.has(sendWhitespaceTag)

	//TODO:	warn that the message was received unencrypted
	if c.msgState != plainText || c.Policies.has(requireEncryption) {
		//TODO: returning an error might not be the best semantic to "it worked,
		//but we have to notify you that something unexpected happened"
		//err = errUnexpectedPlainMessage
	}

	return c.processWhitespaceTag(message)
}

func removeOTRMsgEnvelope(msg encodedMessage) []byte {
	return msg[len(msgMarker) : len(msg)-1]
}

func (c *Conversation) decode(encoded encodedMessage) (messageWithHeader, error) {
	encoded = removeOTRMsgEnvelope(encoded)
	msg := make(messageWithHeader, base64.StdEncoding.DecodedLen(len(encoded)))
	msgLen, err := base64.StdEncoding.Decode(msg, encoded)

	if err != nil {
		return nil, errInvalidOTRMessage
	}

	return msg[:msgLen], nil
}

func (c *Conversation) receiveDecoded(message messageWithHeader) (plain MessagePlaintext, toSend messageWithHeader, toSendExtra messageWithHeader, err error) {
	if err = c.checkVersion(message); err != nil {
		return
	}

	var messageHeader, messageBody []byte
	if messageHeader, messageBody, err = c.parseMessageHeader(message); err != nil {
		return
	}

	msgType := message[2]
	if msgType == msgTypeData {
		plain, toSend, toSendExtra, err = c.maybeHeartbeat(c.processDataMessage(messageHeader, messageBody))
	} else {
		toSend, err = c.potentialAuthError(c.receiveAKE(msgType, messageBody))
	}

	return
}

func (c *Conversation) Receive(message ValidMessage) (plain MessagePlaintext, toSend []ValidMessage, err error) {
	if !c.Policies.isOTREnabled() {
		return c.receiveWithoutOTR(message)
	}

	msgType := guessMessageType(message)
	switch msgType {
	case msgGuessError:
		return c.receiveErrorMessage(message)
	case msgGuessQuery:
		return c.toSendEncoded2(c.receiveQueryMessage(message))
	case msgGuessTaggedPlaintext:
		return c.toSendEncoded3(c.receiveTaggedPlaintext(message))
	case msgGuessNotOTR:
		return c.toSendEncoded3(c.receivePlaintext(message))
	case msgGuessV1KeyExch:
		// TODO: warn here
		return
	case msgGuessFragment:
		// TODO: fix fragment here
		return
	case msgGuessUnknown:
		// TODO: event here
		return
	case msgGuessDHCommit, msgGuessDHKey, msgGuessRevealSig, msgGuessSignature, msgGuessData:
		return c.toSendEncoded34(c.receiveEncoded(encodedMessage(message)))
	}
	return // should never be possible
}
