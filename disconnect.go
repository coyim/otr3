package otr3

func (c *Conversation) processDisconnectedTLV(t tlv) (toSend *tlv, err error) {
	c.msgState = finished
	c.keys = keyManagementContext{}

	return nil, nil
}
