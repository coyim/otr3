package otr3

// Authenticate should be called when the user wants to initiate an authentication session.
func (c *Conversation) Authenticate(mutualSecret []byte) ([][]byte, error) {
	if !c.IsEncrypted() {
		return nil, errCantAuthenticateWithoutEncryption
	}

	// Using ssid here should always be safe - we can't be in an encrypted state without having gone through the AKE
	c.smp.secret = generateSMPSecret(c.ourKey.PublicKey.DefaultFingerprint(), c.theirKey.DefaultFingerprint(), c.ssid[:], mutualSecret)

	// if we are already in SMP state we should abort first, here
	s1, _ := c.generateSMP1()

	c.smp.s1 = &s1

	return c.encode(c.genDataMsg(nil, s1.msg.tlv()).serialize(c)), nil
}
