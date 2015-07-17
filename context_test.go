package otr3

import "testing"

func Test_receive_OTRQueryMsgRepliesWithDHCommitMessage(t *testing.T) {
	msg := []byte("?OTRv3?")
	c := newConversation(nil, fixtureRand())
	c.addPolicy(allowV3)

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
	cxt.addPolicy(allowV3)

	cxt.receive(msg)

	assertDeepEquals(t, cxt.otrContext.otrVersion, otrV3{})
	assertDeepEquals(t, cxt.akeContext.otrVersion, otrV3{})
}

func Test_receiveVerifiesMessageProtocolVersion(t *testing.T) {
	// protocol version
	msg := []byte{0x00, 0x02}
	c := newConversation(otrV3{}, fixtureRand())

	_, err := c.receive(msg)
	assertEquals(t, err, errWrongProtocolVersion)
}

func Test_receive_DHCommitMessageReturnsDHKeyForOTR3(t *testing.T) {
	exp := []byte{
		0x00, 0x03, // protocol version
		msgTypeDHKey,
	}

	dhCommitAKE := fixtureAKE()
	dhCommitMsg, _ := dhCommitAKE.dhCommitMessage()

	c := newConversation(otrV3{}, fixtureRand())
	c.addPolicy(allowV3)

	dhKeyMsg, err := c.receive(dhCommitMsg)

	assertEquals(t, err, nil)
	assertDeepEquals(t, dhKeyMsg[:lenMsgHeader], exp)
}

func Test_receive_DHKeyMessageReturnsRevealSignature(t *testing.T) {
	v := otrV3{}

	c := newConversation(v, fixtureRand())
	msg := fixtureDHKeyMsg(v)
	c.akeContext = bobStateAtAwaitingDHKey()

	toSend, err := c.receive(msg)

	assertEquals(t, err, nil)
	assertDeepEquals(t, dhMsgType(toSend), msgTypeRevealSig)
}
