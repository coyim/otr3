package otr3

// StartAuthenticate should be called when the user wants to initiate authentication with a peer.
// The authentication uses an optional question message and a shared secret. The authentication will proceed
// until the event handler reports that SMP is complete, that a secret is needed or that SMP has failed.
func (c *Conversation) StartAuthenticate(question string, mutualSecret []byte) ([][]byte, error) {
	if !c.IsEncrypted() {
		return nil, errCantAuthenticateWithoutEncryption
	}

	// Using ssid here should always be safe - we can't be in an encrypted state without having gone through the AKE
	c.smp.secret = generateSMPSecret(c.OurKey.PublicKey.DefaultFingerprint(), c.TheirKey.DefaultFingerprint(), c.ssid[:], mutualSecret)

	var tlvs []tlv

	if (c.smp.state != smpStateExpect1{}) {
		tlvs = append(tlvs, smpMessageAbort{}.tlv())
	}

	s1, ok := c.generateSMP1()

	if !ok {
		return nil, errShortRandomRead
	}

	if question != "" {
		s1.msg.hasQuestion = true
		s1.msg.question = question
	}

	c.smp.s1 = &s1

	tlvs = append(tlvs, s1.msg.tlv())

	return c.encode(c.genDataMsg(nil, tlvs...).serialize(c)), nil
}
