package otr3

func (c *Conversation) processDisconnectedTLV(t tlv) (toSend *tlv, err error) {
	//TODO: send event MessageEventConnectionEnded

	c.msgState = finished
	c.keys = keyManagementContext{}

	return nil, nil
}
