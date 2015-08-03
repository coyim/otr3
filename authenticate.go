package otr3

// StartAuthenticate should be called when the user wants to initiate authentication with a peer.
// The authentication uses an optional question message and a shared secret. The authentication will proceed
// until the event handler reports that SMP is complete, that a secret is needed or that SMP has failed.
func (c *Conversation) StartAuthenticate(question string, mutualSecret []byte) ([][]byte, error) {
	tlvs, err := c.smp.state.startAuthenticate(c, question, mutualSecret)

	if err != nil {
		return nil, err
	}

	return c.encode(c.genDataMsg(nil, tlvs...).serialize(c)), nil
}
