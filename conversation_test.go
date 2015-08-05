package otr3

import (
	"crypto/rand"
	"math/big"
	"testing"
)

func Test_receive_OTRQueryMsgRepliesWithDHCommitMessage(t *testing.T) {
	msg := []byte("?OTRv3?")
	c := newConversation(nil, fixtureRand())
	c.Policies.add(allowV3)

	exp := messageWithHeader{
		0x00, 0x03, // protocol version
		msgTypeDHCommit,
	}

	_, enc, err := c.Receive(msg)
	toSend, _ := c.decode(encodedMessage(enc[0]))

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
	exp := messageWithHeader{
		0x00, 0x03, // protocol version
		msgTypeDHKey,
	}

	dhCommitAKE := fixtureConversation()
	dhCommitMsg, _ := dhCommitAKE.dhCommitMessage()
	dhCommitMsg, _ = dhCommitAKE.wrapMessageHeader(msgTypeDHCommit, dhCommitMsg)

	c := newConversation(otrV3{}, fixtureRand())
	c.Policies.add(allowV3)

	_, dhKeyMsg, err := c.receiveDecoded(dhCommitMsg)

	assertEquals(t, err, nil)
	assertDeepEquals(t, dhKeyMsg[0][:messageHeaderPrefix], exp)
}

func Test_receive_DHKeyMessageReturnsRevealSignature(t *testing.T) {
	v := otrV3{}

	msg := fixtureDHKeyMsg(v)
	c := bobContextAtAwaitingDHKey()

	_, toSend, err := c.receiveDecoded(msg)

	assertEquals(t, err, nil)
	assertDeepEquals(t, dhMsgType(toSend[0]), msgTypeRevealSig)
}

func Test_OTRisDisabledIfNoVersionIsAllowedInThePolicy(t *testing.T) {
	msg := []byte("?OTRv3?")

	c := newConversation(nil, fixtureRand())

	s, _ := c.Send(msg)
	assertDeepEquals(t, s, []ValidMessage{msg})

	_, r, err := c.Receive(msg)
	assertNil(t, err)
	assertNil(t, r)
}

func Test_Send_returnsErrorIfFaislToGenerateDataMsg(t *testing.T) {
	msg := []byte("hello")

	c := bobContextAfterAKE()
	c.msgState = encrypted
	c.Policies = policies(allowV3)
	c.keys.theirKeyID = 0
	s, err := c.Send(msg)

	assertNil(t, s)
	assertEquals(t, err, ErrGPGConflict)
}

func Test_send_appendWhitespaceTagsWhenAllowedbyThePolicy(t *testing.T) {
	expectedWhitespaceTag := ValidMessage{
		0x20, 0x09, 0x20, 0x20, 0x09, 0x09, 0x09, 0x09,
		0x20, 0x09, 0x20, 0x09, 0x20, 0x09, 0x20, 0x20,
		0x20, 0x20, 0x09, 0x09, 0x20, 0x20, 0x09, 0x09,
	}

	c := &Conversation{}
	c.Policies = policies(allowV3 | sendWhitespaceTag)

	m, _ := c.Send([]byte("hello"))
	wsPos := len(m[0]) - len(expectedWhitespaceTag)
	assertDeepEquals(t, m[0][wsPos:], expectedWhitespaceTag)
}

func Test_send_doesNotAppendWhitespaceTagsWhenItsNotAllowedbyThePolicy(t *testing.T) {
	m := []byte("hello")
	c := &Conversation{}
	c.Policies = policies(allowV3)

	toSend, _ := c.Send(m)
	assertDeepEquals(t, toSend, []ValidMessage{m})
}

func Test_send_dataMessageWhenItsMsgStateEncrypted(t *testing.T) {
	m := []byte("hello")
	c := bobContextAfterAKE()
	c.msgState = encrypted
	c.Policies = policies(allowV3)
	toSend, _ := c.Send(m)

	stub := bobContextAfterAKE()
	stub.msgState = encrypted
	expected, err := stub.createSerializedDataMessage(m, messageFlagNormal, []tlv{})

	assertDeepEquals(t, err, nil)
	assertDeepEquals(t, toSend, expected)
}

func Test_encodeWithoutFragment(t *testing.T) {
	c := newConversation(otrV2{}, fixtureRand())
	c.Policies = policies(allowV2 | allowV3 | whitespaceStartAKE)
	c.setFragmentSize(64)

	msg := c.encode([]byte("one two three"))

	expectedFragments := []ValidMessage{
		[]byte("?OTR:b25lIHR3byB0aHJlZQ==."),
	}
	assertDeepEquals(t, msg, expectedFragments)
}

func Test_encodeWithoutFragmentTooSmall(t *testing.T) {
	c := newConversation(otrV2{}, fixtureRand())
	c.Policies = policies(allowV2 | allowV3 | whitespaceStartAKE)
	c.setFragmentSize(18)

	msg := c.encode([]byte("one two three"))

	expectedFragments := []ValidMessage{
		[]byte("?OTR:b25lIHR3byB0aHJlZQ==."),
	}
	assertDeepEquals(t, msg, expectedFragments)
}

func Test_encodeWithFragment(t *testing.T) {
	c := newConversation(otrV2{}, fixtureRand())
	c.Policies = policies(allowV2 | allowV3 | whitespaceStartAKE)
	c.setFragmentSize(22)

	msg := c.encode([]byte("one two three"))

	expectedFragments := []ValidMessage{
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
	msg, err := c.End()
	assertNil(t, err)
	assertNil(t, msg)
}

func Test_End_whenStateIsFinished(t *testing.T) {
	c := newConversation(otrV2{}, fixtureRand())
	c.msgState = finished
	msg, err := c.End()
	assertDeepEquals(t, c.msgState, plainText)
	assertNil(t, err)
	assertNil(t, msg)
}

func Test_End_whenStateIsEncrypted(t *testing.T) {
	bob := bobContextAfterAKE()
	bob.msgState = encrypted
	msg, _ := bob.End()
	stub := bobContextAfterAKE()
	expectedMsg, err := stub.createSerializedDataMessage(nil, messageFlagIgnoreUnreadable, []tlv{tlv{tlvType: tlvTypeDisconnected}})

	assertDeepEquals(t, err, nil)
	assertDeepEquals(t, bob.msgState, plainText)
	assertDeepEquals(t, msg, expectedMsg)
}

func Test_End_wipesKeys(t *testing.T) {
	bob := bobContextAfterAKE()
	bob.msgState = encrypted
	bob.End()
	stub := bobContextAfterAKE()
	stub.createSerializedDataMessage(nil, messageFlagIgnoreUnreadable, []tlv{tlv{tlvType: tlvTypeDisconnected}})

	assertDeepEquals(t, dhKeyPair{}, bob.keys.ourCurrentDHKeys)
	assertDeepEquals(t, dhKeyPair{}, bob.keys.ourPreviousDHKeys)
	assertDeepEquals(t, eq(bob.keys.theirCurrentDHPubKey, big.NewInt(0)), true)
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

func Test_receive_ignoresMessagesWithWrongInstanceTags(t *testing.T) {
	bob := newConversation(otrV3{}, rand.Reader)
	bob.Policies.add(allowV3)
	bob.OurKey = bobPrivateKey

	var msg []byte
	msg, bob.keys = fixtureDataMsg(plainDataMsg{})

	bob.ourInstanceTag = 0x1000 // different than the fixture
	bob.keys.ourKeyID = 1       //this would force key rotation
	plain, toSend, err := bob.Receive(bob.encode(msg)[0])
	assertNil(t, plain)
	assertNil(t, toSend)
	assertNil(t, err)
}

func Test_receive_displayErrorMessageToTheUser(t *testing.T) {
	msg := []byte("?OTR Error:You are wrong")
	c := &Conversation{}
	c.Policies.add(allowV3)
	plain, toSend, err := c.Receive(msg)

	assertNil(t, err)
	assertDeepEquals(t, plain, MessagePlaintext("You are wrong"))
	assertNil(t, toSend)
}

func Test_receive_displayErrorMessageToTheUserAndStartAKE(t *testing.T) {
	msg := []byte("?OTR Error:You are wrong")
	c := &Conversation{}
	c.Policies.add(allowV3)
	c.Policies.add(errorStartAKE)
	plain, toSend, err := c.Receive(msg)

	assertEquals(t, err, nil)
	assertDeepEquals(t, plain, MessagePlaintext("You are wrong"))
	assertDeepEquals(t, toSend[0], ValidMessage("?OTRv3?"))
}
