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

func Test_receiveOTRQueryMessageReturnsErrorForOTRV1(t *testing.T) {
	msg := []byte("?OTR?")
	cxt := context{Rand: fixtureRand()}
	err := cxt.receiveOTRQueryMessage(msg)

	assertEquals(t, err, errUnsupportedOTRVersion)
}

func Test_receiveOTRQueryMessageAcceptsOTRV2(t *testing.T) {
	msg := []byte("?OTR?v2?")
	cxt := context{Rand: fixtureRand()}
	err := cxt.receiveOTRQueryMessage(msg)

	assertEquals(t, err, nil)
	assertEquals(t, cxt.version, otrV2{})
}

func Test_receiveOTRQueryMessageAcceptsOTRV3EvenIfV2IsAnOption(t *testing.T) {
	msg := []byte("?OTRv32?")
	cxt := context{Rand: fixtureRand()}
	err := cxt.receiveOTRQueryMessage(msg)

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
