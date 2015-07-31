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
		keysToSignWith: keys.sendingMACKey,
	}

	return dataMessage
}

func (c *Conversation) processDataMessage(msg []byte) (plain, toSend []byte, err error) {
	dataMessage := dataMsg{}

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
