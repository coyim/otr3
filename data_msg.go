package otr3

func (c *akeContext) genDataMsg(tlvs ...[]byte) []byte {
	var out []byte

	//TODO: if msgState != encrypted should error

	out = appendShort(out, c.protocolVersion())
	out = append(out, msgTypeData)

	//TODO
	if c.needInstanceTag() {
		out = appendWord(out, uint32(0))
		out = appendWord(out, uint32(0))
	}

	//TODO: implement IGNORE_UNREADABLE
	out = append(out, 0x00)

	senderKeyID := c.ourKeyID - 1
	recipientKeyID := c.theirKeyID
	out = appendWord(out, senderKeyID)
	out = appendWord(out, recipientKeyID)

	dhy := c.ourCurrentDHKeys.pub
	out = appendMPI(out, dhy)

	//TODO
	var crt [8]byte
	out = append(out, crt[:]...)

	//tlv is properly formatted
	var data []byte
	for _, tlv := range tlvs {
		data = append(data, tlv...)
	}

	//TODO encrypt
	out = append(out, data...)

	//TODO Authenticator (MAC)
	//TODO Old MAC keys to be revealed (DATA)

	return out
}