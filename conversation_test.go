package otr3

import "testing"

func Test_receive_OTRQueryMsgRepliesWithDHCommitMessage(t *testing.T) {
	msg := []byte("?OTRv3?")
	c := newConversation(nil, fixtureRand())
	c.policies.add(allowV3)

	exp := []byte{
		0x00, 0x03, // protocol version
		msgTypeDHCommit,
	}

	toSend, err := c.receive(msg)

	assertEquals(t, err, nil)
	assertDeepEquals(t, toSend[:3], exp)
}

func Test_receive_OTRQueryMsgChangesContextProtocolVersion(t *testing.T) {
	msg := []byte("?OTRv3?")
	cxt := newConversation(nil, fixtureRand())
	cxt.policies.add(allowV3)

	cxt.receive(msg)

	assertDeepEquals(t, cxt.version, otrV3{})
}

func Test_receiveVerifiesMessageProtocolVersion(t *testing.T) {
	// protocol version
	msg := []byte{0x00, 0x02}
	c := newConversation(otrV3{}, fixtureRand())

	_, err := c.receive(msg)

	assertEquals(t, err, errWrongProtocolVersion)
}

func Test_receive_returnsAnErrorForAnInvalidOTRMessageWithoutVersionData(t *testing.T) {
	msg := []byte{0x00}
	c := newConversation(otrV3{}, fixtureRand())

	_, err := c.receive(msg)

	assertEquals(t, err, errInvalidOTRMessage)
}

func Test_receive_returnsAnErrorForADataMessageWhenNoEncryptionIsActive(t *testing.T) {
	m := []byte{
		0x00, 0x03, // protocol version
		msgTypeData,
	}
	c := newConversation(otrV3{}, fixtureRand())

	_, err := c.receive(m)
	assertDeepEquals(t, err, errEncryptedMessageWithNoSecureChannel)
}

func Test_receive_returnsAnErrorForAnIncorrectTLVMessage(t *testing.T) {
	m := []byte{
		0x00, 0x03, // protocol version
		msgTypeData,
		0x99,
	}
	c := newConversation(otrV3{}, fixtureRand())
	c.msgState = encrypted
	_, err := c.receive(m)
	assertDeepEquals(t, err, newOtrError("corrupt data message"))
}

func Test_receive_DHCommitMessageReturnsDHKeyForOTR3(t *testing.T) {
	exp := []byte{
		0x00, 0x03, // protocol version
		msgTypeDHKey,
	}

	dhCommitAKE := fixtureConversation()
	dhCommitMsg, _ := dhCommitAKE.dhCommitMessage()

	c := newConversation(otrV3{}, fixtureRand())
	c.policies.add(allowV3)

	dhKeyMsg, err := c.receive(dhCommitMsg)

	assertEquals(t, err, nil)
	assertDeepEquals(t, dhKeyMsg[:lenMsgHeader], exp)
}

func Test_receive_DHKeyMessageReturnsRevealSignature(t *testing.T) {
	v := otrV3{}

	msg := fixtureDHKeyMsg(v)
	c := bobContextAtAwaitingDHKey()

	toSend, err := c.receive(msg)

	assertEquals(t, err, nil)
	assertDeepEquals(t, dhMsgType(toSend), msgTypeRevealSig)
}

func Test_randMPI_returnsNotOKForAShortRead(t *testing.T) {
	c := newConversation(otrV3{}, fixedRand([]string{"ABCD"}))
	var buf [3]byte

	_, ok := c.randMPI(buf[:])
	assertEquals(t, ok, false)
}

func Test_randMPI_returnsOKForARealRead(t *testing.T) {
	c := newConversation(otrV3{}, fixedRand([]string{"ABCD"}))
	var buf [2]byte

	_, ok := c.randMPI(buf[:])
	assertEquals(t, ok, true)
}

func Test_genDataMsg_withKeyExchangeData(t *testing.T) {
	c := bobContextAfterAKE()
	c.keys.ourKeyID = 2
	c.keys.theirKeyID = 3
	c.keys.ourCounter = 0x1011121314

	dataMsg := c.genDataMsg(nil)

	assertEquals(t, dataMsg.senderKeyID, uint32(1))
	assertEquals(t, dataMsg.recipientKeyID, uint32(3))
	assertDeepEquals(t, dataMsg.y, c.keys.ourCurrentDHKeys.pub)
	assertDeepEquals(t, dataMsg.topHalfCtr, [8]byte{
		0x00, 0x00, 0x00, 0x10, 0x11, 0x12, 0x13, 0x14,
	})
	assertEquals(t, c.keys.ourCounter, uint64(0x1011121314+1))
}

func Test_genDataMsg_hasEncryptedMessage(t *testing.T) {
	c := bobContextAfterAKE()

	expected := bytesFromHex("4f0de18011633ed0264ccc1840d64f4cf8f0c91ef78890ab82edef36cb38210bb80760585ff43d736a9ff3e4bb05fc088fa34c2f21012988d539ebc839e9bc97633f4c42de15ea5c3c55a2b9940ca35015ded14205b9df78f936cb1521aedbea98df7dc03c116570ba8d034abc8e2d23185d2ce225845f38c08cb2aae192d66d601c1bc86149c98e8874705ae365b31cda76d274429de5e07b93f0ff29152716980a63c31b7bda150b222ba1d373f786d5f59f580d4f690a71d7fc620e0a3b05d692221ddeebac98d6ed16272e7c4596de27fb104ad747aa9a3ad9d3bc4f988af0beb21760df06047e267af0109baceb0f363bcaff7b205f2c42b3cb67a942f2")
	dataMsg := c.genDataMsg([]byte("we are awesome"))

	assertDeepEquals(t, dataMsg.encryptedMsg, expected)
}

func Test_genDataMsg_revealOldMACKeysFromKeyManagementContext(t *testing.T) {
	oldMACKeys := []macKey{
		macKey{0x00, 0x01, 0x02, 0x03, 0x00, 0x01, 0x02, 0x03, 0x00, 0x01, 0x02, 0x03, 0x00, 0x01, 0x02, 0x03, 0x00, 0x01, 0x02, 0x03},
		macKey{0x01, 0x01, 0x02, 0x03, 0x00, 0x01, 0x02, 0x03, 0x00, 0x01, 0x02, 0x03, 0x00, 0x01, 0x02, 0x03, 0x00, 0x01, 0x02, 0x03},
	}

	c := bobContextAfterAKE()
	c.keys.oldMACKeys = oldMACKeys

	dataMsg := c.genDataMsg(nil)

	assertDeepEquals(t, dataMsg.oldMACKeys, oldMACKeys)
}
