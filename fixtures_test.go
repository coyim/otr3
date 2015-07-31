package otr3

func fixtureConversation() *Conversation {
	return fixtureConversationWithVersion(otrV3{})
}

func fixtureConversationV2() *Conversation {
	return fixtureConversationWithVersion(otrV2{})
}

func fixtureConversationWithVersion(v otrVersion) *Conversation {
	return newConversation(v, fixtureRand())
}

func fixtureDHCommitMsg() []byte {
	c := fixtureConversation()
	msg, _ := c.dhCommitMessage()
	return msg
}

func fixtureDHCommitMsgBody() []byte {
	return fixtureDHCommitMsg()[otrv3HeaderLen:]
}

func fixtureDHCommitMsgV2() []byte {
	c := fixtureConversationV2()
	msg, _ := c.dhCommitMessage()
	return msg
}

func fixtureDHKeyMsg(v otrVersion) []byte {
	c := fixtureConversationWithVersion(v)
	c.ourKey = alicePrivateKey
	msg, _ := c.dhKeyMessage()
	return msg
}

func fixtureDHKeyMsgBody(v otrVersion) []byte {
	val := otrV2{}
	if val == v {
		return fixtureDHKeyMsg(v)[otrv2HeaderLen:]
	} else {
		return fixtureDHKeyMsg(v)[otrv3HeaderLen:]
	}
}

func fixtureRevealSigMsg(v otrVersion) []byte {
	c := bobContextAtReceiveDHKey()
	c.version = v

	msg, _ := c.revealSigMessage()

	return msg
}

func fixtureSigMsg(v otrVersion) []byte {
	c := aliceContextAtReceiveRevealSig()
	c.version = v

	msg, _ := c.sigMessage()

	return msg
}

func bobContextAfterAKE() *Conversation {
	c := newConversation(otrV3{}, fixtureRand())
	c.keys.ourKeyID = 1
	c.keys.ourCurrentDHKeys.pub = fixedgx
	c.keys.ourPreviousDHKeys.priv = fixedx
	c.keys.ourPreviousDHKeys.pub = fixedgx

	c.keys.theirKeyID = 1
	c.keys.theirCurrentDHPubKey = fixedgy

	return c
}

func bobContextAtAwaitingSig() *Conversation {
	c := bobContextAtReceiveDHKey()
	c.version = otrV2{}
	c.policies.add(allowV2)
	c.ake.state = authStateAwaitingSig{}

	return c
}

func bobContextAtReceiveDHKey() *Conversation {
	c := bobContextAtAwaitingDHKey()
	c.ake.theirPublicValue = fixedgy // stored at receiveDHKey

	copy(c.ake.sigKey.c[:], bytesFromHex("d942cc80b66503414c05e3752d9ba5c4"))
	copy(c.ake.sigKey.m1[:], bytesFromHex("b6254b8eab0ad98152949454d23c8c9b08e4e9cf423b27edc09b1975a76eb59c"))
	copy(c.ake.sigKey.m2[:], bytesFromHex("954be27015eeb0455250144d906e83e7d329c49581aea634c4189a3c981184f5"))

	return c
}

func bobContextAtAwaitingDHKey() *Conversation {
	c := newConversation(otrV3{}, fixtureRand())
	c.startAKE()
	c.policies.add(allowV3)
	c.ake.state = authStateAwaitingDHKey{}
	c.ourKey = bobPrivateKey

	copy(c.ake.r[:], fixedr)    // stored at sendDHCommit
	c.setSecretExponent(fixedx) // stored at sendDHCommit

	return c
}

func aliceContextAtReceiveRevealSig() *Conversation {
	c := aliceContextAtAwaitingRevealSig()
	c.ake.theirPublicValue = fixedgx // Alice decrypts encryptedGx using r

	return c
}

func aliceContextAtAwaitingRevealSig() *Conversation {
	c := newConversation(otrV2{}, fixtureRand())
	c.startAKE()
	c.policies.add(allowV2)
	c.ake.state = authStateAwaitingRevealSig{}
	c.ourKey = alicePrivateKey

	copy(c.ake.hashedGx[:], expectedHashedGxValue) //stored at receiveDHCommit
	c.ake.encryptedGx = expectedEncryptedGxValue   //stored at receiveDHCommit

	c.setSecretExponent(fixedy) //stored at sendDHKey

	return c
}

//Alice generates a encrypted message to Bob
//Fixture data msg never rotates the receiver keys when the returned context is
//used before receiving the message
func fixtureDataMsg(plain plainDataMsg) ([]byte, keyManagementContext) {
	var senderKeyID uint32 = 1
	var recipientKeyID uint32 = 1

	//We use a combination of ourKeyId, theirKeyID, senderKeyID and recipientKeyID
	//to make sure both sender and receiver will use the same DH session keys
	receiverContext := keyManagementContext{
		ourCounter:   1,
		theirCounter: 1,

		ourKeyID:   senderKeyID + 1,
		theirKeyID: recipientKeyID + 1,
		ourCurrentDHKeys: dhKeyPair{
			priv: fixedy,
			pub:  fixedgy,
		},
		ourPreviousDHKeys: dhKeyPair{
			priv: fixedy,
			pub:  fixedgy,
		},
		theirCurrentDHPubKey:  fixedgx,
		theirPreviousDHPubKey: fixedgx,
	}

	keys := calculateDHSessionKeys(fixedx, fixedgx, fixedgy)

	m := dataMsg{
		senderKeyID:    senderKeyID,
		recipientKeyID: recipientKeyID,

		y:          fixedgy, //this is alices current Pub
		topHalfCtr: [8]byte{0, 0, 0, 0, 0, 0, 0, 2},
	}

	m.encryptedMsg = plain.encrypt(keys.sendingAESKey, m.topHalfCtr)
	m.sign(keys.sendingMACKey)

	return m.serialize(newConversation(otrV3{}, nil)), receiverContext
}

//Alice decrypts a encrypted message from Bob, generated after receiving
//an encrypted message from Alice generated with fixtureDataMsg()
func fixtureDecryptDataMsg(encryptedDataMsg []byte) plainDataMsg {
	c := newConversation(otrV3{}, nil)
	withoutHeader, _ := c.parseMessageHeader(encryptedDataMsg)

	m := dataMsg{}
	m.deserialize(withoutHeader)

	keys := calculateDHSessionKeys(fixedx, fixedgx, fixedgy)

	exp := plainDataMsg{}
	exp.decrypt(keys.receivingAESKey, m.topHalfCtr, m.encryptedMsg)

	return exp
}
