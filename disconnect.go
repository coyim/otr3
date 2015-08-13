package otr3

func (c *Conversation) processDisconnectedTLV(t tlv, x dataMessageExtra) (toSend *tlv, err error) {
	previousMsgState := c.msgState

	defer c.signalSecurityEventIf(previousMsgState == encrypted, GoneInsecure)
	c.msgState = finished

	c.keys = keyManagementContext{}

	return nil, nil
}
