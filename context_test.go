package otr3

import "testing"

var (
	fixtureX  = bnFromHex("abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd")
	fixtureGx = bnFromHex("2cdacabb00e63d8949aa85f7e6a095b1ee81a60779e58f8938ff1a7ed1e651d954bd739162e699cc73b820728af53aae60a46d529620792ddf839c5d03d2d4e92137a535b27500e3b3d34d59d0cd460d1f386b5eb46a7404b15c1ef84840697d2d3d2405dcdda351014d24a8717f7b9c51f6c84de365fea634737ae18ba22253a8e15249d9beb2dded640c6c0d74e4f7e19161cf828ce3ffa9d425fb68c0fddcaa7cbe81a7a5c2c595cce69a255059d9e5c04b49fb15901c087e225da850ff27")
)

func Test_receive_OTRQueryMsgRepliesWithDHCommitMessage(t *testing.T) {
	msg := []byte("?OTRv3?")
	c := newConversation(nil, fixtureRand())
	c.addPolicy(allowV3)

	exp := []byte{
		0x00, 0x03, // protocol version
		0x02, //DH message type
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
		0x0A, //DH message type
	}

	dhCommitAKE := fixtureAKE()
	dhCommitMsg, _ := dhCommitAKE.dhCommitMessage()

	c := newConversation(otrV3{}, fixtureRand())
	c.addPolicy(allowV3)

	dhKeyMsg, err := c.receive(dhCommitMsg)

	assertEquals(t, err, nil)
	assertDeepEquals(t, dhKeyMsg[:lenMsgHeader], exp)
}
