package otr3

import (
	"crypto/rand"
	"testing"
)

func Test_receive_OTRQueryMsgRepliesWithDHCommitMessage(t *testing.T) {
	msg := []byte("?OTRv3?")
	c := newConversation(nil, fixtureRand())
	c.Policies.add(allowV3)

	exp := []byte{
		0x00, 0x03, // protocol version
		msgTypeDHCommit,
	}

	_, enc, err := c.Receive(msg)
	toSend, _ := c.decode(enc[0])

	assertEquals(t, err, nil)
	assertDeepEquals(t, toSend[:3], exp)
}

func Test_receive_OTRQueryMsgChangesContextProtocolVersion(t *testing.T) {
	msg := []byte("?OTRv3?")
	c := newConversation(nil, fixtureRand())
	c.Policies.add(allowV3)

	_, _, err := c.Receive(msg)

	assertEquals(t, err, nil)
	assertDeepEquals(t, c.version, otrV3{})
}

func Test_receive_verifiesMessageProtocolVersion(t *testing.T) {
	// protocol version
	msg := []byte{0x00, 0x02, 0x00, msgTypeDHKey}
	c := newConversation(otrV3{}, fixtureRand())

	_, _, err := c.receiveDecoded(msg)

	assertEquals(t, err, errWrongProtocolVersion)
}

func Test_receive_returnsAnErrorForAnInvalidOTRMessageWithoutVersionData(t *testing.T) {
	msg := []byte{0x00}
	c := newConversation(otrV3{}, fixtureRand())

	_, _, err := c.receiveDecoded(msg)

	assertEquals(t, err, errInvalidOTRMessage)
}

func Test_receive_returnsAnErrorForADataMessageWhenNoEncryptionIsActive(t *testing.T) {
	m := []byte{
		0x00, 0x03, // protocol version
		msgTypeData,
		0x00, 0x00, 0x01, 0x01,
		0x00, 0x00, 0x01, 0x01,
	}
	c := newConversation(otrV3{}, fixtureRand())

	_, _, err := c.receiveDecoded(m)
	assertDeepEquals(t, err, errEncryptedMessageWithNoSecureChannel)
}

func Test_receive_DHCommitMessageReturnsDHKeyForOTR3(t *testing.T) {
	exp := []byte{
		0x00, 0x03, // protocol version
		msgTypeDHKey,
	}

	dhCommitAKE := fixtureConversation()
	dhCommitMsg, _ := dhCommitAKE.dhCommitMessage()

	c := newConversation(otrV3{}, fixtureRand())
	c.Policies.add(allowV3)

	_, dhKeyMsg, err := c.receiveDecoded(dhCommitMsg)

	assertEquals(t, err, nil)
	assertDeepEquals(t, dhKeyMsg[:messageHeaderPrefix], exp)
}

func Test_receive_DHKeyMessageReturnsRevealSignature(t *testing.T) {
	v := otrV3{}

	msg := fixtureDHKeyMsg(v)
	c := bobContextAtAwaitingDHKey()

	_, toSend, err := c.receiveDecoded(msg)

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

func Test_OTRisDisabledIfNoVersionIsAllowedInThePolicy(t *testing.T) {
	var nilB [][]byte
	msg := []byte("?OTRv3?")

	c := newConversation(nil, fixtureRand())

	s, _ := c.Send(msg)
	assertDeepEquals(t, s, [][]byte{msg})

	_, r, err := c.Receive(msg)
	assertEquals(t, err, nil)
	assertDeepEquals(t, r, nilB)
}

func Test_send_appendWhitespaceTagsWhenAllowedbyThePolicy(t *testing.T) {
	expectedWhitespaceTag := []byte{
		0x20, 0x09, 0x20, 0x20, 0x09, 0x09, 0x09, 0x09,
		0x20, 0x09, 0x20, 0x09, 0x20, 0x09, 0x20, 0x20,
		0x20, 0x20, 0x09, 0x09, 0x20, 0x20, 0x09, 0x09,
	}

	c := newConversation(nil, nil)
	c.Policies = policies(allowV3 | sendWhitespaceTag)

	m, _ := c.Send([]byte("hello"))
	wsPos := len(m[0]) - len(expectedWhitespaceTag)
	assertDeepEquals(t, m[0][wsPos:], expectedWhitespaceTag)
}

func Test_send_doesNotAppendWhitespaceTagsWhenItsNotAllowedbyThePolicy(t *testing.T) {
	m := []byte("hello")
	c := newConversation(nil, nil)
	c.Policies = policies(allowV3)

	toSend, _ := c.Send(m)
	assertDeepEquals(t, toSend, [][]byte{m})
}

func Test_send_dataMessageWhenItsMsgStateEncrypted(t *testing.T) {
	m := []byte("hello")
	c := bobContextAfterAKE()
	c.msgState = encrypted
	c.Policies = policies(allowV3)
	toSend, _ := c.Send(m)

	stub := bobContextAfterAKE()
	stub.msgState = encrypted
	expected := stub.encode(stub.genDataMsg(m).serialize(stub))

	assertDeepEquals(t, toSend, expected)
}

func Test_encodeWithoutFragment(t *testing.T) {
	c := newConversation(otrV2{}, fixtureRand())
	c.Policies = policies(allowV2 | allowV3 | whitespaceStartAKE)
	c.setFragmentSize(64)

	msg := c.encode([]byte("one two three"))

	expectedFragments := [][]byte{
		[]byte("?OTR:b25lIHR3byB0aHJlZQ==."),
	}
	assertDeepEquals(t, msg, expectedFragments)
}

func Test_encodeWithoutFragmentTooSmall(t *testing.T) {
	c := newConversation(otrV2{}, fixtureRand())
	c.Policies = policies(allowV2 | allowV3 | whitespaceStartAKE)
	c.setFragmentSize(18)

	msg := c.encode([]byte("one two three"))

	expectedFragments := [][]byte{
		[]byte("?OTR:b25lIHR3byB0aHJlZQ==."),
	}
	assertDeepEquals(t, msg, expectedFragments)
}

func Test_encodeWithFragment(t *testing.T) {
	c := newConversation(otrV2{}, fixtureRand())
	c.Policies = policies(allowV2 | allowV3 | whitespaceStartAKE)
	c.setFragmentSize(22)

	msg := c.encode([]byte("one two three"))

	expectedFragments := [][]byte{
		[]byte("?OTR,00001,00007,?OTR,"),
		[]byte("?OTR,00002,00007,:b25,"),
		[]byte("?OTR,00003,00007,lIHR,"),
		[]byte("?OTR,00004,00007,3byB,"),
		[]byte("?OTR,00005,00007,0aHJ,"),
		[]byte("?OTR,00006,00007,lZQ=,"),
		[]byte("?OTR,00007,00007,=.,"),
	}

	assertDeepEquals(t, msg, expectedFragments)
}

func Test_End_whenStateIsPlainText(t *testing.T) {
	c := newConversation(otrV2{}, fixtureRand())
	c.msgState = plainText
	msg := c.End()
	assertDeepEquals(t, msg, [][]uint8(nil))
}

func Test_End_whenStateIsFinished(t *testing.T) {
	c := newConversation(otrV2{}, fixtureRand())
	c.msgState = finished
	msg := c.End()
	assertDeepEquals(t, c.msgState, plainText)
	assertDeepEquals(t, msg, [][]uint8(nil))
}

func Test_End_whenStateIsEncrypted(t *testing.T) {
	bob := bobContextAfterAKE()
	bob.msgState = encrypted
	msg := bob.End()
	stub := bobContextAfterAKE()
	expected := stub.encode(stub.genDataMsg(nil, tlv{tlvType: tlvTypeDisconnected}).serialize(stub))

	assertDeepEquals(t, bob.msgState, plainText)
	assertDeepEquals(t, msg, expected)
}

func Test_receive_canDecodeOTRMessagesWithoutFragments(t *testing.T) {
	c := newConversation(otrV2{}, rand.Reader)
	c.Policies.add(allowV2)

	dhCommitMsg := []byte("?OTR:AAICAAAAxPWaCOvRNycg72w2shQjcSEiYjcTh+w7rq+48UM9mpZIkpN08jtTAPcc8/9fcx9mmlVy/We+n6/G65RvobYWPoY+KD9Si41TFKku34gU4HaBbwwa7XpB/4u1gPCxY6EGe0IjthTUGK2e3qLf9YCkwJ1lm+X9kPOS/Jqu06V0qKysmbUmuynXG8T5Q8rAIRPtA/RYMqSGIvfNcZfrlJRIw6M784YtWlF3i2B6dmtjMrjH/8x5myN++Q2bxh69g6z/WX1rAFoAAAAg7Vwgf3JoiH5MdRznnS3aL66tjxQzN5qiwLtImE+KFnM=.")
	_, _, err := c.Receive(dhCommitMsg)

	assertEquals(t, err, nil)
	assertEquals(t, c.ake.state, authStateAwaitingRevealSig{})
	assertEquals(t, c.version, otrV2{})
}

func Test_receive_ignoresMesagesWithWrongInstanceTags(t *testing.T) {
	bob := newConversation(otrV3{}, nil)
	bob.Policies.add(allowV3)
	bob.OurKey = bobPrivateKey

	var msg []byte
	msg, bob.keys = fixtureDataMsg(plainDataMsg{})

	bob.ourInstanceTag = 0x1000 // different than the fixture
	bob.keys.ourKeyID = 1       //this would force key rotation
	_, _, err := bob.Receive(bob.encode(msg)[0])
	assertDeepEquals(t, err, errReceivedMessageForOtherInstance)
}

func Test_receive_displayErrorMessageToTheUser(t *testing.T) {
	var nilB [][]byte

	msg := []byte("?OTR Error:You are wrong")
	c := newConversation(nil, nil)
	c.Policies.add(allowV3)
	plain, toSend, err := c.Receive(msg)

	assertEquals(t, err, nil)
	assertDeepEquals(t, plain, []byte("You are wrong"))
	assertDeepEquals(t, toSend, nilB)
}

func Test_receive_displayErrorMessageToTheUserAndStartAKE(t *testing.T) {
	msg := []byte("?OTR Error:You are wrong")
	c := newConversation(nil, nil)
	c.Policies.add(allowV3)
	c.Policies.add(errorStartAKE)
	plain, toSend, err := c.Receive(msg)

	assertEquals(t, err, nil)
	assertDeepEquals(t, plain, []byte("You are wrong"))
	assertDeepEquals(t, toSend[0], []byte("?OTRv3?"))
}
