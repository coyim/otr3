package otr3

import "testing"

func Test_receiveQueryMessage_SendDHCommitAndTransitToStateAwaitingDHKey(t *testing.T) {
	queryMsg := []byte("?OTRv3?")

	c := newConversation(nil, fixtureRand())
	c.Policies.add(allowV3)
	msg, _ := c.receiveQueryMessage(queryMsg)

	assertEquals(t, c.ake.state, authStateAwaitingDHKey{})
	assertDeepEquals(t, dhMsgType(msg), msgTypeDHCommit)
}

func Test_receiveQueryMessage_signalsMessageEventOnFailure(t *testing.T) {
	queryMsg := []byte("?OTRv3?")

	c := newConversation(nil, fixedRand([]string{"ABCD"}))
	c.Policies.add(allowV3)
	c.expectMessageEvent(t, func() {
		c.receiveQueryMessage(queryMsg)
	}, MessageEventSetupError, "", errShortRandomRead)
}

func Test_receiveQueryMessageV2_SendDHCommitv2(t *testing.T) {
	queryMsg := []byte("?OTRv2?")

	c := newConversation(nil, fixtureRand())
	c.Policies.add(allowV2)
	msg, _ := c.receiveQueryMessage(queryMsg)

	assertDeepEquals(t, dhMsgType(msg), msgTypeDHCommit)
	assertDeepEquals(t, dhMsgVersion(msg), uint16(2))
}

func Test_receiveQueryMessage_StoresRAndXAndGx(t *testing.T) {
	fixture := fixtureConversation()
	fixture.dhCommitMessage()

	msg := []byte("?OTRv3?")
	cxt := newConversation(nil, fixtureRand())
	cxt.Policies.add(allowV3)

	cxt.receiveQueryMessage(msg)
	assertDeepEquals(t, cxt.ake.r, fixture.ake.r)
	assertDeepEquals(t, cxt.ake.secretExponent, fixture.ake.secretExponent)
	assertDeepEquals(t, cxt.ake.ourPublicValue, fixture.ake.ourPublicValue)
}

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

func Test_acceptOTRRequest_returnsNilForUnsupportedVersions(t *testing.T) {
	p := policies(0)
	msg := []byte("?OTR?")
	v, ok := acceptOTRRequest(p, msg)

	assertEquals(t, v, nil)
	assertEquals(t, ok, false)
}

func Test_acceptOTRRequest_acceptsOTRV3IfHasAllowV3Policy(t *testing.T) {
	msg := []byte("?OTRv32?")
	p := policies(0)
	p.AllowV2()
	p.allowV3()
	v, ok := acceptOTRRequest(p, msg)

	assertEquals(t, v, otrV3{})
	assertEquals(t, ok, true)
}

func Test_acceptOTRRequest_acceptsOTRV2IfHasOnlyAllowV2Policy(t *testing.T) {
	msg := []byte("?OTRv32?")
	p := policies(0)
	p.AllowV2()
	v, ok := acceptOTRRequest(p, msg)

	assertEquals(t, v, otrV2{})
	assertEquals(t, ok, true)
}
