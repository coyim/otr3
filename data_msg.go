package otr3

func (c *akeContext) genDataMsg(tlvs ...tlv) dataMsg {
	msgHeader := messageHeader{
		protocolVersion:     c.protocolVersion(),
		needInstanceTag:     c.needInstanceTag(),
		senderInstanceTag:   uint32(0),
		receiverInstanceTag: uint32(0),
	}

	dataMessage := dataMsg{
		messageHeader: msgHeader,
		//TODO: implement IGNORE_UNREADABLE
		flag: 0x00,

		senderKeyID:    c.ourKeyID - 1,
		recipientKeyID: c.theirKeyID,
		y:              c.ourCurrentDHKeys.pub,
		topHalfCtr:     [8]byte{},
		//tlv is properly formatted
		dataMsgEncrypted: []byte{},
		//TODO after key management
		authenticator:   [20]byte{},
		oldRevealKeyMAC: []byte{},
	}

	return dataMessage
}
