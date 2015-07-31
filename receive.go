package otr3

func (c *Conversation) Receive(message []byte) (plain []byte, toSend [][]byte, err error) {
	var unencodedReturn []byte

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
		c.whitespaceTagIgnored = c.policies.has(sendWhitespaceTag)

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
