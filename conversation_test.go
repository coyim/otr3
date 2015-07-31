package otr3

import (
	"crypto/rand"
	"io"
	"testing"
)

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

func newConversation(v otrVersion, rand io.Reader) *Conversation {
	var p policy
	switch v {
	case otrV3{}:
		p = allowV3
	case otrV2{}:
		p = allowV2
	}
	akeNotStarted := new(ake)
	akeNotStarted.state = authStateNone{}

	return &Conversation{
		version: v,
		Rand:    rand,
		smp: smp{
			state: smpStateExpect1{},
		},
		ake:          akeNotStarted,
		policies:     policies(p),
		fragmentSize: 65535, //we are not testing fragmentation by default
	}
}

func Test_receive_OTRQueryMsgRepliesWithDHCommitMessage(t *testing.T) {
	msg := []byte("?OTRv3?")
	c := newConversation(nil, fixtureRand())
	c.policies.add(allowV3)

	exp := []byte{
		0x00, 0x03, // protocol version
		msgTypeDHCommit,
	}

	_, toSend, err := c.receiveDecoded(msg)

	assertEquals(t, err, nil)
	assertDeepEquals(t, toSend[:3], exp)
}

func Test_receive_OTRQueryMsgChangesContextProtocolVersion(t *testing.T) {
	msg := []byte("?OTRv3?")
	cxt := newConversation(nil, fixtureRand())
	cxt.policies.add(allowV3)

	cxt.receiveDecoded(msg)

	assertDeepEquals(t, cxt.version, otrV3{})
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
	c.policies.add(allowV3)

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
	c.policies = policies(allowV3 | sendWhitespaceTag)

	m, _ := c.Send([]byte("hello"))
	wsPos := len(m[0]) - len(expectedWhitespaceTag)
	assertDeepEquals(t, m[0][wsPos:], expectedWhitespaceTag)
}

func Test_send_doesNotAppendWhitespaceTagsWhenItsNotAllowedbyThePolicy(t *testing.T) {
	m := []byte("hello")
	c := newConversation(nil, nil)
	c.policies = policies(allowV3)

	toSend, _ := c.Send(m)
	assertDeepEquals(t, toSend, [][]byte{m})
}

func Test_send_dataMessageWhenItsMsgStateEncrypted(t *testing.T) {
	m := []byte("hello")
	c := bobContextAfterAKE()
	c.msgState = encrypted
	c.policies = policies(allowV3)
	toSend, _ := c.Send(m)

	stub := bobContextAfterAKE()
	stub.msgState = encrypted
	expected := stub.encode(stub.genDataMsg(m).serialize(stub))

	assertDeepEquals(t, toSend, expected)
}

func Test_receive_acceptsV2WhitespaceTagAndStartsAKE(t *testing.T) {
	c := newConversation(nil, fixtureRand())
	c.policies = policies(allowV2 | whitespaceStartAKE)

	msg := genWhitespaceTag(policies(allowV2))

	_, toSend, err := c.receiveDecoded(msg)

	assertEquals(t, err, nil)
	assertEquals(t, dhMsgType(toSend), msgTypeDHCommit)
	assertEquals(t, dhMsgVersion(toSend), uint16(2))
}

func Test_receive_ignoresV2WhitespaceTagIfThePolicyDoesNotHaveWhitespaceStartAKE(t *testing.T) {
	var nilB []byte
	c := newConversation(nil, fixtureRand())
	c.policies = policies(allowV2 | ^whitespaceStartAKE)

	msg := genWhitespaceTag(policies(allowV2))

	_, toSend, err := c.receiveDecoded(msg)

	//FIXME: err should be nil, but at the moment is not possible to distinguish
	//between plaintext messages and OTR-encoded messages
	assertEquals(t, err, errInvalidOTRMessage)
	assertDeepEquals(t, toSend, nilB)
}

func Test_receive_failsWhenReceivesV2WhitespaceTagIfV2IsNotInThePolicy(t *testing.T) {
	var nilB []byte
	c := newConversation(nil, fixtureRand())
	c.policies = policies(allowV3 | whitespaceStartAKE)

	msg := genWhitespaceTag(policies(allowV2))

	_, toSend, err := c.receiveDecoded(msg)

	assertEquals(t, err, errInvalidVersion)
	assertDeepEquals(t, toSend, nilB)
}

func Test_receive_acceptsV3WhitespaceTagAndStartsAKE(t *testing.T) {
	c := newConversation(nil, fixtureRand())
	c.policies = policies(allowV2 | allowV3 | whitespaceStartAKE)

	msg := genWhitespaceTag(policies(allowV2 | allowV3))

	_, toSend, err := c.receiveDecoded(msg)

	assertEquals(t, err, nil)
	assertEquals(t, dhMsgType(toSend), msgTypeDHCommit)
	assertEquals(t, dhMsgVersion(toSend), uint16(3))
}

func Test_receive_ignoresV3WhitespaceTagIfThePolicyDoesNotHaveWhitespaceStartAKE(t *testing.T) {
	var nilB []byte
	c := newConversation(nil, fixtureRand())
	c.policies = policies(allowV2 | allowV3 | ^whitespaceStartAKE)

	msg := genWhitespaceTag(policies(allowV3))

	_, toSend, err := c.receiveDecoded(msg)

	//FIXME: err should be nil, but at the moment is not possible to distinguish
	//between plaintext messages and OTR-encoded messages
	assertEquals(t, err, errInvalidOTRMessage)
	assertDeepEquals(t, toSend, nilB)
}

func Test_receive_failsWhenReceivesV3WhitespaceTagIfV3IsNotInThePolicy(t *testing.T) {
	var nilB []byte
	c := newConversation(nil, fixtureRand())
	c.policies = policies(allowV2 | whitespaceStartAKE)

	msg := genWhitespaceTag(policies(allowV3))

	_, toSend, err := c.receiveDecoded(msg)

	assertEquals(t, err, errInvalidVersion)
	assertDeepEquals(t, toSend, nilB)
}

func Test_encodeWithoutFragment(t *testing.T) {
	c := newConversation(otrV2{}, fixtureRand())
	c.policies = policies(allowV2 | allowV3 | whitespaceStartAKE)
	c.setFragmentSize(64)

	msg := c.encode([]byte("one two three"))

	expectedFragments := [][]byte{
		[]byte("?OTR:b25lIHR3byB0aHJlZQ==."),
	}
	assertDeepEquals(t, msg, expectedFragments)
}

func Test_encodeWithoutFragmentTooSmall(t *testing.T) {
	c := newConversation(otrV2{}, fixtureRand())
	c.policies = policies(allowV2 | allowV3 | whitespaceStartAKE)
	c.setFragmentSize(18)

	msg := c.encode([]byte("one two three"))

	expectedFragments := [][]byte{
		[]byte("?OTR:b25lIHR3byB0aHJlZQ==."),
	}
	assertDeepEquals(t, msg, expectedFragments)
}

func Test_encodeWithFragment(t *testing.T) {
	c := newConversation(otrV2{}, fixtureRand())
	c.policies = policies(allowV2 | allowV3 | whitespaceStartAKE)
	c.setFragmentSize(22)

	msg := c.encode([]byte("one two three"))

	//FIXME: old implementation is not having leading zero in fragment index, who is correct?
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
	msg, _ := c.End()
	assertDeepEquals(t, msg, [][]uint8(nil))
}

func Test_End_whenStateIsFinished(t *testing.T) {
	c := newConversation(otrV2{}, fixtureRand())
	c.msgState = finished
	msg, _ := c.End()
	assertDeepEquals(t, c.msgState, plainText)
	assertDeepEquals(t, msg, [][]uint8(nil))
}

func Test_End_whenStateIsEncrypted(t *testing.T) {
	bob := bobContextAfterAKE()
	bob.msgState = encrypted
	msg, _ := bob.End()
	stub := bobContextAfterAKE()
	expected := stub.encode(stub.genDataMsg(nil, tlv{tlvType: tlvTypeDisconnected}).serialize(stub))

	assertDeepEquals(t, bob.msgState, plainText)
	assertDeepEquals(t, msg, expected)
}

func Test_receive_canDecodeOTRMessagesWithoutFragments(t *testing.T) {
	c := newConversation(nil, rand.Reader)
	c.policies.add(allowV2)

	dhCommitMsg := []byte("?OTR:AAICAAAAxPWaCOvRNycg72w2shQjcSEiYjcTh+w7rq+48UM9mpZIkpN08jtTAPcc8/9fcx9mmlVy/We+n6/G65RvobYWPoY+KD9Si41TFKku34gU4HaBbwwa7XpB/4u1gPCxY6EGe0IjthTUGK2e3qLf9YCkwJ1lm+X9kPOS/Jqu06V0qKysmbUmuynXG8T5Q8rAIRPtA/RYMqSGIvfNcZfrlJRIw6M784YtWlF3i2B6dmtjMrjH/8x5myN++Q2bxh69g6z/WX1rAFoAAAAg7Vwgf3JoiH5MdRznnS3aL66tjxQzN5qiwLtImE+KFnM=.")
	_, _, err := c.Receive(dhCommitMsg)

	assertEquals(t, err, nil)
	assertEquals(t, c.ake.state, authStateAwaitingRevealSig{})
	assertEquals(t, c.version, otrV2{})
}
