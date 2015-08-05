package otr3

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

func (c *Conversation) encodeAndCombine(toSend []messageWithHeader) []ValidMessage {
	var result []ValidMessage

	for _, ts := range toSend {
		result = append(result, c.encode(ts)...)
	}

	return result
}

func (c *Conversation) toSendEncoded(plain MessagePlaintext, toSend []messageWithHeader, err error) (MessagePlaintext, []ValidMessage, error) {
	if err != nil || len(toSend) == 0 || len(toSend[0]) == 0 {
		return plain, nil, err
	}

	return plain, c.encodeAndCombine(toSend), err
}

func (c *Conversation) receiveEncoded(message encodedMessage) (MessagePlaintext, []messageWithHeader, error) {
	decodedMessage, err := c.decode(message)
	if err != nil {
		return nil, nil, err
	}
	return c.receiveDecoded(decodedMessage)
}

func (c *Conversation) checkPlaintextPolicies(plain MessagePlaintext) {
	c.stopSendingWhitespaceTags = c.Policies.has(sendWhitespaceTag)

	if c.msgState != plainText || c.Policies.has(requireEncryption) {
		messageEventReceivedUnencryptedMessage(c, plain)
	}
}

func (c *Conversation) receivePlaintext(message ValidMessage) (plain MessagePlaintext, toSend []messageWithHeader, err error) {
	plain = MessagePlaintext(message)
	c.checkPlaintextPolicies(plain)
	return
}

func (c *Conversation) receiveTaggedPlaintext(message ValidMessage) (plain MessagePlaintext, toSend []messageWithHeader, err error) {
	plain, toSend, err = c.processWhitespaceTag(message)
	c.checkPlaintextPolicies(plain)
	return
}

func removeOTRMsgEnvelope(msg encodedMessage) []byte {
	return msg[len(msgMarker) : len(msg)-1]
}

func (c *Conversation) decode(encoded encodedMessage) (messageWithHeader, error) {
	encoded = removeOTRMsgEnvelope(encoded)
	msg, err := b64decode(encoded)

	if err != nil {
		return nil, errInvalidOTRMessage
	}

	return msg, nil
}

func (c *Conversation) receiveDecoded(message messageWithHeader) (plain MessagePlaintext, toSend []messageWithHeader, err error) {
	if err = c.checkVersion(message); err != nil {
		return
	}

	var messageHeader, messageBody []byte
	if messageHeader, messageBody, err = c.parseMessageHeader(message); err != nil {
		if err == errReceivedMessageForOtherInstance {
			err = nil
		}
		return
	}

	msgType := message[2]
	if msgType == msgTypeData {
		plain, toSend, err = c.maybeHeartbeat(c.processDataMessage(messageHeader, messageBody))
		if err != nil {
			messageEventReceivedUnreadableMessage(c)
		}
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
	var messagesToSend []messageWithHeader
	switch msgType {
	case msgGuessError:
		return c.receiveErrorMessage(message)
	case msgGuessQuery:
		messagesToSend, err = c.receiveQueryMessage(message)
	case msgGuessTaggedPlaintext:
		plain, messagesToSend, err = c.receiveTaggedPlaintext(message)
	case msgGuessNotOTR:
		plain, messagesToSend, err = c.receivePlaintext(message)
	case msgGuessV1KeyExch:
		// TODO: warn here
	case msgGuessFragment:
		// TODO: fix fragment here
	case msgGuessUnknown:
		messageEventReceivedUnrecognizedMessage(c)
	case msgGuessDHCommit, msgGuessDHKey, msgGuessRevealSig, msgGuessSignature, msgGuessData:
		plain, messagesToSend, err = c.receiveEncoded(encodedMessage(message))
	}

	return c.toSendEncoded(plain, messagesToSend, err)
}
