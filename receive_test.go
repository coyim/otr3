package otr3

import "testing"

var (
	fixtureX  = bnFromHex("abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd")
	fixtureGx = bnFromHex("2cdacabb00e63d8949aa85f7e6a095b1ee81a60779e58f8938ff1a7ed1e651d954bd739162e699cc73b820728af53aae60a46d529620792ddf839c5d03d2d4e92137a535b27500e3b3d34d59d0cd460d1f386b5eb46a7404b15c1ef84840697d2d3d2405dcdda351014d24a8717f7b9c51f6c84de365fea634737ae18ba22253a8e15249d9beb2dded640c6c0d74e4f7e19161cf828ce3ffa9d425fb68c0fddcaa7cbe81a7a5c2c595cce69a255059d9e5c04b49fb15901c087e225da850ff27")
)

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

func Test_receiveOTRQueryMessageStoresXAndGx(t *testing.T) {
	msg := []byte("?OTRv3?")
	cxt := context{Rand: fixtureRand()}

	_, err := cxt.receiveOTRQueryMessage(msg)
	assertEquals(t, err, nil)
	assertDeepEquals(t, cxt.x, fixtureX)
	assertDeepEquals(t, cxt.gx, fixtureGx)
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

func Test_receiveDHKeyMessageGeneratesDHRevealSigMessage(t *testing.T) {
	exp := []byte{
		0x00, 0x03, // protocol version
		msgTypeRevealSig, // type
	}

	cxt := newContext(otrV3{}, fixtureRand())
	cxt.x = fixtureX
	cxt.gx = fixtureGx
	cxt.privateKey = bobPrivateKey

	ake := AKE{
		context: cxt,
	}

	dhKeyMsg, _ := ake.dhKeyMessage()

	dhRevealSigMsg, err := cxt.receiveDHKey(dhKeyMsg)
	assertEquals(t, err, nil)
	assertDeepEquals(t, dhRevealSigMsg[:lenMsgHeader], exp)
}
