package otr3

import "testing"

func Test_smpStateExpect1_goToExpectState3WhenReceivesSmpMessage1(t *testing.T) {
	c := newSmpContext(otrV3{}, fixtureRand())
	c.secret = bnFromHex("ABCDE56321F9A9F8E364607C8C82DECD8E8E6209E2CB952C7E649620F5286FE3")

	msg := fixtureMessage1()
	nextState, _ := smpStateExpect1{}.receiveMessage1(c, msg)

	assertEquals(t, nextState, smpStateExpect3{})
}

func Test_smpStateExpect1_returnsSmpMessageAbortIfReceivesUnexpectedMessage(t *testing.T) {
	state := smpStateExpect1{}
	c := newSmpContext(otrV3{}, fixtureRand())
	_, msg := state.receiveMessage2(c, smpMessage2{})
	assertDeepEquals(t, msg, smpMessageAbort{})

	_, msg = state.receiveMessage3(c, smpMessage3{})
	assertDeepEquals(t, msg, smpMessageAbort{})

	_, msg = state.receiveMessage4(c, smpMessage4{})
	assertDeepEquals(t, msg, smpMessageAbort{})
}

func Test_smpStateExpect2_goToExpectState4WhenReceivesSmpMessage2(t *testing.T) {
	c := newSmpContext(otrV3{}, fixtureRand())
	c.secret = bnFromHex("ABCDE56321F9A9F8E364607C8C82DECD8E8E6209E2CB952C7E649620F5286FE3")
	c.s1 = fixtureSmp1()

	msg := fixtureMessage2()
	nextState, _ := smpStateExpect2{}.receiveMessage2(c, msg)

	assertEquals(t, nextState, smpStateExpect4{})
}

func Test_smpStateExpect2_returnsSmpMessageAbortIfReceivesUnexpectedMessage(t *testing.T) {
	state := smpStateExpect2{}
	c := newSmpContext(otrV3{}, fixtureRand())
	_, msg := state.receiveMessage1(c, smpMessage1{})
	assertDeepEquals(t, msg, smpMessageAbort{})

	_, msg = state.receiveMessage3(c, smpMessage3{})
	assertDeepEquals(t, msg, smpMessageAbort{})

	_, msg = state.receiveMessage4(c, smpMessage4{})
	assertDeepEquals(t, msg, smpMessageAbort{})
}

func Test_smpStateExpect3_goToExpectState1WhenReceivesSmpMessage3(t *testing.T) {
	c := newSmpContext(otrV3{}, fixtureRand())
	c.secret = bnFromHex("ABCDE56321F9A9F8E364607C8C82DECD8E8E6209E2CB952C7E649620F5286FE3")
	c.s2 = fixtureSmp2()
	msg := fixtureMessage3()

	nextState, _ := smpStateExpect3{}.receiveMessage3(c, msg)

	assertEquals(t, nextState, smpStateExpect1{})
}

func Test_smpStateExpect3_returnsSmpMessageAbortIfReceivesUnexpectedMessage(t *testing.T) {
	state := smpStateExpect3{}
	c := newSmpContext(otrV3{}, fixtureRand())
	_, msg := state.receiveMessage1(c, smpMessage1{})
	assertDeepEquals(t, msg, smpMessageAbort{})

	_, msg = state.receiveMessage2(c, smpMessage2{})
	assertDeepEquals(t, msg, smpMessageAbort{})

	_, msg = state.receiveMessage4(c, smpMessage4{})
	assertDeepEquals(t, msg, smpMessageAbort{})
}

func Test_smpStateExpect4_goToExpectState1WhenReceivesSmpMessage4(t *testing.T) {
	c := newSmpContext(otrV3{}, fixtureRand())
	c.s1 = fixtureSmp1()
	c.s3 = fixtureSmp3()
	msg := fixtureMessage4()

	nextState, _ := smpStateExpect4{}.receiveMessage4(c, msg)

	assertEquals(t, nextState, smpStateExpect1{})
}

func Test_smpStateExpect4_returnsSmpMessageAbortIfReceivesUnexpectedMessage(t *testing.T) {
	state := smpStateExpect4{}
	c := newSmpContext(otrV3{}, fixtureRand())
	_, msg := state.receiveMessage1(c, smpMessage1{})
	assertDeepEquals(t, msg, smpMessageAbort{})

	_, msg = state.receiveMessage2(c, smpMessage2{})
	assertDeepEquals(t, msg, smpMessageAbort{})

	_, msg = state.receiveMessage3(c, smpMessage3{})
	assertDeepEquals(t, msg, smpMessageAbort{})
}

func Test_contextTransitionsFromSmpExpect1ToSmpExpect3(t *testing.T) {
	m := fixtureMessage1()
	c := newConversation(otrV3{}, fixtureRand())
	c.secret = bnFromHex("ABCDE56321F9A9F8E364607C8C82DECD8E8E6209E2CB952C7E649620F5286FE3")

	c.smpContext.receive(m.tlv())
	assertEquals(t, c.smpState, smpStateExpect3{})
}

func Test_contextTransitionsFromSmpExpect2ToSmpExpect4(t *testing.T) {
	m := fixtureMessage2()
	c := newConversation(otrV3{}, fixtureRand())
	c.smpState = smpStateExpect2{}
	c.smpContext.s1 = fixtureSmp1()
	c.smpContext.secret = bnFromHex("ABCDE56321F9A9F8E364607C8C82DECD8E8E6209E2CB952C7E649620F5286FE3")

	c.smpContext.receive(m.tlv())
	assertEquals(t, c.smpState, smpStateExpect4{})
}

func Test_contextTransitionsFromSmpExpect3ToSmpExpect1(t *testing.T) {
	m := fixtureMessage3()
	c := newConversation(otrV3{}, fixtureRand())
	c.smpState = smpStateExpect3{}
	c.smpContext.s2 = fixtureSmp2()
	c.smpContext.secret = bnFromHex("ABCDE56321F9A9F8E364607C8C82DECD8E8E6209E2CB952C7E649620F5286FE3")

	c.smpContext.receive(m.tlv())
	assertEquals(t, c.smpState, smpStateExpect1{})
}

func Test_contextTransitionsFromSmpExpect4ToSmpExpect1(t *testing.T) {
	m := fixtureMessage4()
	c := newConversation(otrV3{}, fixtureRand())
	c.smpState = smpStateExpect4{}
	c.smpContext.s1 = fixtureSmp1()
	c.smpContext.s3 = fixtureSmp3()

	c.smpContext.receive(m.tlv())
	assertEquals(t, c.smpState, smpStateExpect1{})
}

func Test_contextUnexpectedMessageTransitionsToSmpExpected1(t *testing.T) {
	m := fixtureMessage1()

	c := newConversation(otrV3{}, fixtureRand())
	c.smpState = smpStateExpect3{}
	toSend := c.smpContext.receive(m.tlv())

	assertEquals(t, c.smpState, smpStateExpect1{})
	assertDeepEquals(t, toSend, smpMessageAbort{}.tlv())
}
