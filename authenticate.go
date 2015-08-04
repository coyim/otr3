package otr3

// StartAuthenticate should be called when the user wants to initiate authentication with a peer.
// The authentication uses an optional question message and a shared secret. The authentication will proceed
// until the event handler reports that SMP is complete, that a secret is needed or that SMP has failed.
func (c *Conversation) StartAuthenticate(question string, mutualSecret []byte) ([][]byte, error) {
	tlvs, err := c.smp.state.startAuthenticate(c, question, mutualSecret)

	if err != nil {
		return nil, err
	}

	return c.createSerializedDataMessage(nil, messageFlagIgnoreUnreadable, tlvs)
}

// ProvideAuthenticationSecret should be called when the peer has started an authentication request, and the UI has been notified that a secret is needed
// It is only valid to call this function if the current SMP state is waiting for a secret to be provided. The return is the potential messages to send.
func (c *Conversation) ProvideAuthenticationSecret(mutualSecret []byte) ([][]byte, error) {
	t, err := c.continueSMP(mutualSecret)
	if err != nil {
		return nil, err
	}
	return c.createSerializedDataMessage(nil, messageFlagIgnoreUnreadable, []tlv{*t})
}

func (c *Conversation) createSerializedDataMessage(msg []byte, flag byte, tlvs []tlv) ([][]byte, error) {
	dataMsg, err := c.genDataMsgWithFlag(msg, flag, tlvs...)
	if err != nil {
		return nil, err
	}

	res, err := c.wrapMessageHeader(msgTypeData, dataMsg.serialize())
	if err != nil {
		return nil, err
	}
	c.updateLastSent()
	return c.encode(res), nil
}

func (c *Conversation) potentialAuthError(toSend []byte, err error) ([]byte, error) {
	if err != nil {
		messageEventSetupError(c, err)
	}
	return toSend, err
}
