package otr3

import "testing"

func Test_parseOTRQueryMessage(t *testing.T) {
	var exp = map[string][]int{
		"?OTR?":     []int{1},
		"?OTRv2?":   []int{2},
		"?OTRv23?":  []int{2, 3},
		"?OTR?v2":   []int{1, 2},
		"?OTRv248?": []int{2, 4, 8},
		"?OTR?v?":   []int{1},
		"?OTRv?":    []int{},
	}

	for queryMsg, versions := range exp {
		m := []byte(queryMsg)
		assertDeepEquals(t, parseOTRQueryMessage(m), versions)
	}
}

func Test_acceptOTRRequestReturnsErrorForOTRV1(t *testing.T) {
	msg := []byte("?OTR?")
	cxt := context{Rand: fixtureRand()}
	err := cxt.acceptOTRRequest(msg)

	assertEquals(t, err, errUnsupportedOTRVersion)
}

func Test_acceptOTRRequestAcceptsOTRV2(t *testing.T) {
	msg := []byte("?OTR?v2?")
	cxt := context{Rand: fixtureRand()}
	err := cxt.acceptOTRRequest(msg)

	assertEquals(t, err, nil)
	assertEquals(t, cxt.version, otrV2{})
}

func Test_acceptOTRRequestAcceptsOTRV3EvenIfV2IsAnOption(t *testing.T) {
	msg := []byte("?OTRv32?")
	cxt := context{Rand: fixtureRand()}
	err := cxt.acceptOTRRequest(msg)

	assertEquals(t, err, nil)
	assertEquals(t, cxt.version, otrV3{})
}

func Test_receiveSendsDHCommitMessageAfterReceivingAnOTRQueryMessage(t *testing.T) {
	msg := []byte("?OTRv3?")
	cxt := context{Rand: fixtureRand()}

	exp := []byte{
		0x00, 0x03, // protocol version
		0x02, //DH message type
	}

	toSend, err := cxt.receive(msg)

	assertEquals(t, err, nil)
	assertDeepEquals(t, toSend[:3], exp)
}

func Test_receiveVerifiesMessageProtocolVersion(t *testing.T) {
	// protocol version
	msg := []byte{0x00, 0x02}
	cxt := newContext(otrV3{}, fixtureRand())

	_, err := cxt.receive(msg)
	assertEquals(t, err, errWrongProtocolVersion)
}

func Test_receiveDHCommitMessageReturnsDHKeyForOTR3(t *testing.T) {
	exp := []byte{
		0x00, 0x03, // protocol version
		0x0A, //DH message type
	}

	cxt := newContext(otrV3{}, fixtureRand())
	ake := AKE{
		context: cxt,
	}

	dhCommitMsg, _ := ake.dhCommitMessage()
	dhKeyMsg, err := cxt.receiveDHCommit(dhCommitMsg)

	assertEquals(t, err, nil)
	assertDeepEquals(t, dhKeyMsg[:lenMsgHeader], exp)
}

func Test_receiveDHCommitMessageGeneratesDHKeyMessageWithCorrectInstanceTags(t *testing.T) {
	cxt := newContext(otrV3{}, fixtureRand())
	senderInstanceTag := uint32(0x00000101)
	posReceiverInsTag := 7

	ake := AKE{
		context:           cxt,
		senderInstanceTag: senderInstanceTag,
	}

	dhCommitMsg, _ := ake.dhCommitMessage()
	dhKeyMsg, err := cxt.receiveDHCommit(dhCommitMsg)
	instTag, _ := extractWord(dhKeyMsg, posReceiverInsTag)

	assertEquals(t, err, nil)
	assertEquals(t, instTag, senderInstanceTag)
}
