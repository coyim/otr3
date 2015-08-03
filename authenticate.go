package otr3

// StartAuthenticate should be called when the user wants to initiate authentication with a peer.
// The authentication uses an optional question message and a shared secret. The authentication will proceed
// until the event handler reports that SMP is complete, that a secret is needed or that SMP has failed.
func (c *Conversation) StartAuthenticate(question string, mutualSecret []byte) ([][]byte, error) {
	tlvs, err := c.smp.state.startAuthenticate(c, question, mutualSecret)

	if err != nil {
		return nil, err
	}

	return c.createSerializedDataMessage(tlvs)
}

func (c *Conversation) createSerializedDataMessage(tlvs []tlv) ([][]byte, error) {
	return c.encode(c.genDataMsg(nil, tlvs...).serialize(c)), nil
}

// ProvideAuthenticationSecret should be called when the peer has started an authentication request, and the UI has been notified that a secret is needed
// It is only valid to call this function if the current SMP state is waiting for a secret to be provided. The return is the potential messages to send.
func (c *Conversation) ProvideAuthenticationSecret(mutualSecret []byte) ([][]byte, error) {
	if !c.IsEncrypted() {
		return nil, errCantAuthenticateWithoutEncryption
	}

	if _, stateOk := c.smp.state.(smpStateWaitingForSecret); !stateOk {
		return nil, errNotWaitingForSMPSecret
	}

	// Using ssid here should always be safe - we can't be in an encrypted state without having gone through the AKE
	c.smp.secret = generateSMPSecret(c.TheirKey.DefaultFingerprint(), c.OurKey.PublicKey.DefaultFingerprint(), c.ssid[:], mutualSecret)

	t, err := c.continueSMP()
	if err != nil {
		return nil, err
	}

	return c.createSerializedDataMessage([]tlv{*t})
}
