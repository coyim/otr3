package otr3

import "errors"

// Send takes a human readable message from the local user, possibly encrypts
// it and returns zero or more messages to send to the peer.
func (c *Conversation) Send(m ValidMessage) ([]ValidMessage, error) {
	message := makeCopy(m)
	defer wipeBytes(message)

	if !c.Policies.isOTREnabled() {
		return []ValidMessage{makeCopy(message)}, nil
	}

	switch c.msgState {
	case plainText:
		return c.sendMessageOnPlaintext(message)
	case encrypted:
		return c.sendMessageOnEncrypted(message)
	case finished:
		messageEventConnectionEnded(c)
		return nil, errors.New("otr: cannot send message because secure conversation has finished")
	}

	return nil, errors.New("otr: cannot send message in current state")
}

func (c *Conversation) sendMessageOnPlaintext(message ValidMessage) ([]ValidMessage, error) {
	if c.Policies.has(requireEncryption) {
		messageEventEncryptionRequired(c)
		c.updateLastSent()
		c.updateMayRetransmitTo(retransmitExact)
		c.lastMessage(MessagePlaintext(makeCopy(message)))
		return []ValidMessage{c.queryMessage()}, nil
	}

	if c.Policies.has(sendWhitespaceTag) {
		message = c.appendWhitespaceTag(message)
	}

	return []ValidMessage{makeCopy(message)}, nil
}

func (c *Conversation) sendMessageOnEncrypted(message ValidMessage) ([]ValidMessage, error) {
	result, err := c.createSerializedDataMessage(message, messageFlagNormal, []tlv{})
	if err != nil {
		messageEventEncryptionError(c)
		if c.getEventHandler().WishToHandleErrorMessage() {
			msg := c.getEventHandler().HandleErrorMessage(ErrorCodeEncryptionError)
			result = []ValidMessage{append(append(errorMarker, ' '), msg...)}
		}
	}

	return result, err
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

	//TODO: In which case Alice's keys are wiped?
	//When she accepts a new DH-Commit?
	c.keys = c.keys.wipeAndKeepRevealKeys()

	return
}
