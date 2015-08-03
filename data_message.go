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

	header, err := c.messageHeader(msgTypeData)
	if err != nil {
		//TODO: errors
		return dataMsg{}
	}

	dataMessage := dataMsg{
		//TODO: implement IGNORE_UNREADABLE
		flag:           0x00,
		messageHeader:  header,
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

func (c *Conversation) processDataMessage(header, msg []byte) (plain, toSend []byte, err error) {
	dataMessage := dataMsg{messageHeader: header}

	if err = dataMessage.deserialize(msg); err != nil {
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
	//Never fails because receivingAESKey is a AES-128 key
	err = p.decrypt(sessionKeys.receivingAESKey, dataMessage.topHalfCtr, dataMessage.encryptedMsg)
	if err != nil {
		return
	}

	plain = p.message
	err = c.rotateKeys(dataMessage)
	if err != nil {
		return
	}

	//TODO: TEST. Should not process TLVs if it fails to rotate keys.
	//This is how libotr does
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

func (c *Conversation) processSMPTLV(t tlv) (toSend *tlv, err error) {
	smpMessage, ok := t.smpMessage()
	if !ok {
		return nil, newOtrError("corrupt data message")
	}

	return c.receiveSMP(smpMessage)
}

func (c *Conversation) processTLVs(tlvs []tlv) ([]tlv, error) {
	var retTLVs []tlv
	var err error

	for _, t := range tlvs {
		mh, e := messageHandlerForTLV(t)
		if e != nil {
			continue
		}

		toSend, err := mh(c, t)
		if err != nil {
			//TODO: Double check how libotr handles this. Should we really stop
			//processing at first error?
			// Nope, we should not.
			return retTLVs, err
		}

		if toSend != nil {
			retTLVs = append(retTLVs, *toSend)
		}
	}

	return retTLVs, err
}
