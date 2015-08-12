package otr3

func (c *Conversation) processDisconnectedTLV(t tlv) (toSend *tlv, err error) {
	previousMsgState := c.msgState

	c.msgState = finished
	c.keys = keyManagementContext{}

	if previousMsgState == encrypted {
		c.securityEvent(GoneInsecure)
	}

	return nil, nil
}
