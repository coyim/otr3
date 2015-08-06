package otr3

import "errors"

func (c *Conversation) Send(msg ValidMessage) ([]ValidMessage, error) {
	if !c.Policies.isOTREnabled() {
		return []ValidMessage{msg}, nil
	}
	switch c.msgState {
	case plainText:
		if c.Policies.has(requireEncryption) {
			messageEventEncryptionRequired(c)
			c.updateLastSent()
			return []ValidMessage{c.queryMessage()}, nil
		}
		if c.Policies.has(sendWhitespaceTag) {
			msg = c.appendWhitespaceTag(msg)
		}
		return []ValidMessage{msg}, nil
	case encrypted:
		result, err := c.createSerializedDataMessage(msg, messageFlagNormal, []tlv{})
		if err != nil {
			messageEventEncryptionError(c)
		}
		return result, err
	case finished:
		messageEventConnectionEnded(c)
		return nil, errors.New("otr: cannot send message because secure conversation has finished")
	}

	return nil, errors.New("otr: cannot send message in current state")
}

func (c *Conversation) fragEncode(msg messageWithHeader) []ValidMessage {
	bytesPerFragment := c.fragmentSize - c.version.minFragmentSize()
	return c.fragment(c.encode(msg), bytesPerFragment)
}

func (c *Conversation) encode(msg messageWithHeader) encodedMessage {
	return append(append(msgMarker, b64encode(msg)...), '.')
}

func (c *Conversation) sendDHCommit() (toSend messageWithHeader, err error) {
	toSend, err = c.dhCommitMessage()
	if err != nil {
		return
	}
	toSend, err = c.wrapMessageHeader(msgTypeDHCommit, toSend)
	if err != nil {
		return nil, err
	}

	c.ake.state = authStateAwaitingDHKey{}
	//TODO: wipe keys from the memory
	c.keys = keyManagementContext{
		oldMACKeys: c.keys.oldMACKeys,
	}
	return
}
