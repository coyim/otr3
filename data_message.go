package otr3

import "encoding/binary"

func (c *Conversation) genDataMsg(message []byte, tlvs ...tlv) dataMsg {
	keys, err := c.keys.calculateDHSessionKeys(c.keys.ourKeyID-1, c.keys.theirKeyID)
	if err != nil {
		//TODO errors
		return dataMsg{}
	}

	topHalfCtr := [8]byte{}
	binary.BigEndian.PutUint64(topHalfCtr[:], c.keys.ourCounter)
	c.keys.ourCounter++

	plain := plainDataMsg{
		message: message,
		tlvs:    tlvs,
	}

	encrypted := plain.encrypt(keys.sendingAESKey, topHalfCtr)
	dataMessage := dataMsg{
		//TODO: implement IGNORE_UNREADABLE
		flag: 0x00,

		senderKeyID:    c.keys.ourKeyID - 1,
		recipientKeyID: c.keys.theirKeyID,
		y:              c.keys.ourCurrentDHKeys.pub,
		topHalfCtr:     topHalfCtr,
		encryptedMsg:   encrypted,
		oldMACKeys:     c.keys.revealMACKeys(),
	}
	dataMessage.sign(keys.sendingMACKey)

	return dataMessage
}

func (c *Conversation) processDataMessage(msg []byte) (plain, toSend []byte, err error) {
	// FIXME: deal with errors in this function
	msg, _ = c.parseMessageHeader(msg)

	dataMessage := dataMsg{}

	err = dataMessage.deserialize(msg)
	if err != nil {
		return
	}

	if err = c.keys.checkMessageCounter(dataMessage); err != nil {
		return
	}

	sessionKeys, err := c.keys.calculateDHSessionKeys(dataMessage.recipientKeyID, dataMessage.senderKeyID)
	if err != nil {
		return
	}

	if err = dataMessage.checkSign(sessionKeys.receivingMACKey); err != nil {
		return
	}

	p := plainDataMsg{}
	err = p.decrypt(sessionKeys.receivingAESKey, dataMessage.topHalfCtr, dataMessage.encryptedMsg)
	if err != nil {
		return
	}

	plain = p.message
	err = c.rotateKeys(dataMessage)
	if err != nil {
		return
	}

	//TODO: TEST. Should not process TLVs if it fails to rotate keys. This is how
	//libotr does
	var tlvs []tlv
	tlvs, err = c.processTLVs(p.tlvs)
	if err != nil {
		return
	}

	if len(tlvs) > 0 {
		toSend = c.genDataMsg(nil, tlvs...).serialize(c)
	}

	return
}

func (c *Conversation) rotateKeys(dataMessage dataMsg) error {
	c.keys.rotateTheirKey(dataMessage.senderKeyID, dataMessage.y)

	x, ok := c.randMPI(make([]byte, 40))
	if !ok {
		//NOTE: what should we do?
		//This is one kind of error that breaks the encrypted channel. I believe we
		//should change the msgState to != encrypted
		return errShortRandomRead
	}

	c.keys.rotateOurKeys(dataMessage.recipientKeyID, x)

	return nil
}

func (c *Conversation) processTLVs(tlvs []tlv) ([]tlv, error) {
	var retTLVs []tlv
	var err error

	for _, tlv := range tlvs {
		if tlv.tlvType == 0x00 {
			continue
		}

		//FIXME: dont need to serialize again
		//Change parseTLV to convert tlv objects to smpMessages
		smpMessage, ok := parseTLV(tlv.serialize())
		if !ok {
			return nil, newOtrError("corrupt data message")
		}

		//FIXME: What if it receives multiple SMP messages in the same data message?
		//FIXME: toSend should be a DATA message. It is a TLV serialized
		tlv, err = c.receiveSMP(smpMessage)
		if err != nil {
			return nil, err
		}

		retTLVs = append(retTLVs, tlv)
	}

	return retTLVs, err
}
