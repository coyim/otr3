package otr3

import (
	"errors"
	"math/big"
	"testing"
)

func Test_smpStateExpect1_goToExpectState3WhenReceivesSmpMessage1(t *testing.T) {
	c := newConversation(otrV3{}, fixtureRand())
	c.secret = bnFromHex("ABCDE56321F9A9F8E364607C8C82DECD8E8E6209E2CB952C7E649620F5286FE3")

	msg := fixtureMessage1()
	nextState, _, _ := smpStateExpect1{}.receiveMessage1(c, msg)

	assertEquals(t, nextState, smpStateExpect3{})
}

func Test_smpStateExpect1_returnsSmpMessageAbortIfReceivesUnexpectedMessage(t *testing.T) {
	state := smpStateExpect1{}
	c := newConversation(otrV3{}, fixtureRand())
	_, msg, _ := state.receiveMessage2(c, smp2Message{})
	assertDeepEquals(t, msg, smpMessageAbort{})

	_, msg, _ = state.receiveMessage3(c, smp3Message{})
	assertDeepEquals(t, msg, smpMessageAbort{})

	_, msg, _ = state.receiveMessage4(c, smp4Message{})
	assertDeepEquals(t, msg, smpMessageAbort{})
}

func Test_smpStateExpect2_goToExpectState4WhenReceivesSmpMessage2(t *testing.T) {
	c := newConversation(otrV3{}, fixtureRand())
	c.secret = bnFromHex("ABCDE56321F9A9F8E364607C8C82DECD8E8E6209E2CB952C7E649620F5286FE3")
	c.s1 = fixtureSmp1()

	msg := fixtureMessage2()
	nextState, _, _ := smpStateExpect2{}.receiveMessage2(c, msg)

	assertEquals(t, nextState, smpStateExpect4{})
}

func Test_smpStateExpect2_returnsSmpMessageAbortIfReceivesUnexpectedMessage(t *testing.T) {
	state := smpStateExpect2{}
	c := newConversation(otrV3{}, fixtureRand())
	_, msg, _ := state.receiveMessage1(c, smp1Message{})
	assertDeepEquals(t, msg, smpMessageAbort{})

	_, msg, _ = state.receiveMessage3(c, smp3Message{})
	assertDeepEquals(t, msg, smpMessageAbort{})

	_, msg, _ = state.receiveMessage4(c, smp4Message{})
	assertDeepEquals(t, msg, smpMessageAbort{})
}

func Test_smpStateExpect3_goToExpectState1WhenReceivesSmpMessage3(t *testing.T) {
	c := newConversation(otrV3{}, fixtureRand())
	c.secret = bnFromHex("ABCDE56321F9A9F8E364607C8C82DECD8E8E6209E2CB952C7E649620F5286FE3")
	c.s2 = fixtureSmp2()
	msg := fixtureMessage3()

	nextState, _, _ := smpStateExpect3{}.receiveMessage3(c, msg)

	assertEquals(t, nextState, smpStateExpect1{})
}

func Test_smpStateExpect3_returnsSmpMessageAbortIfReceivesUnexpectedMessage(t *testing.T) {
	state := smpStateExpect3{}
	c := newConversation(otrV3{}, fixtureRand())
	_, msg, _ := state.receiveMessage1(c, smp1Message{})
	assertDeepEquals(t, msg, smpMessageAbort{})

	_, msg, _ = state.receiveMessage2(c, smp2Message{})
	assertDeepEquals(t, msg, smpMessageAbort{})

	_, msg, _ = state.receiveMessage4(c, smp4Message{})
	assertDeepEquals(t, msg, smpMessageAbort{})
}

func Test_smpStateExpect4_goToExpectState1WhenReceivesSmpMessage4(t *testing.T) {
	c := newConversation(otrV3{}, fixtureRand())
	c.s1 = fixtureSmp1()
	c.s3 = fixtureSmp3()
	msg := fixtureMessage4()

	nextState, _, _ := smpStateExpect4{}.receiveMessage4(c, msg)

	assertEquals(t, nextState, smpStateExpect1{})
}

func Test_smpStateExpect4_returnsSmpMessageAbortIfReceivesUnexpectedMessage(t *testing.T) {
	state := smpStateExpect4{}
	c := newConversation(otrV3{}, fixtureRand())
	_, msg, _ := state.receiveMessage1(c, smp1Message{})
	assertDeepEquals(t, msg, smpMessageAbort{})

	_, msg, _ = state.receiveMessage2(c, smp2Message{})
	assertDeepEquals(t, msg, smpMessageAbort{})

	_, msg, _ = state.receiveMessage3(c, smp3Message{})
	assertDeepEquals(t, msg, smpMessageAbort{})
}

func Test_contextTransitionsFromSmpExpect1ToSmpExpect3(t *testing.T) {
	m := fixtureMessage1()
	c := newConversation(otrV3{}, fixtureRand())
	c.secret = bnFromHex("ABCDE56321F9A9F8E364607C8C82DECD8E8E6209E2CB952C7E649620F5286FE3")

	c.receiveSMP(m)
	assertEquals(t, c.smpState, smpStateExpect3{})
}

func Test_contextTransitionsFromSmpExpect2ToSmpExpect4(t *testing.T) {
	m := fixtureMessage2()
	c := newConversation(otrV3{}, fixtureRand())
	c.smpState = smpStateExpect2{}
	c.s1 = fixtureSmp1()
	c.secret = bnFromHex("ABCDE56321F9A9F8E364607C8C82DECD8E8E6209E2CB952C7E649620F5286FE3")

	c.receiveSMP(m)
	assertEquals(t, c.smpState, smpStateExpect4{})
}

func Test_contextTransitionsFromSmpExpect3ToSmpExpect1(t *testing.T) {
	m := fixtureMessage3()
	c := newConversation(otrV3{}, fixtureRand())
	c.smpState = smpStateExpect3{}
	c.s2 = fixtureSmp2()
	c.secret = bnFromHex("ABCDE56321F9A9F8E364607C8C82DECD8E8E6209E2CB952C7E649620F5286FE3")

	c.receiveSMP(m)
	assertEquals(t, c.smpState, smpStateExpect1{})
}

func Test_contextTransitionsFromSmpExpect4ToSmpExpect1(t *testing.T) {
	m := fixtureMessage4()
	c := newConversation(otrV3{}, fixtureRand())
	c.smpState = smpStateExpect4{}
	c.s1 = fixtureSmp1()
	c.s3 = fixtureSmp3()

	c.receiveSMP(m)
	assertEquals(t, c.smpState, smpStateExpect1{})
}

func Test_contextUnexpectedMessageTransitionsToSmpExpected1(t *testing.T) {
	m := fixtureMessage1()

	c := newConversation(otrV3{}, fixtureRand())
	c.smpState = smpStateExpect3{}
	toSend, err := c.receiveSMP(m)

	assertEquals(t, err, nil)
	assertEquals(t, c.smpState, smpStateExpect1{})
	assertDeepEquals(t, toSend, smpMessageAbort{}.tlv().serialize())
}

func Test_smpStateExpect1_receiveMessage1_returnsErrorIfVerifySMP1ReturnsError(t *testing.T) {
	c := newConversation(otrV3{}, fixtureRand())
	_, _, err := smpStateExpect1{}.receiveMessage1(c, smp1Message{g2a: big.NewInt(1)})

	assertDeepEquals(t, err, errors.New("g2a is an invalid group element"))
}

func Test_smp1Message_receivedMessage_returnsErrorIfreceiveMessage1ReturnsError(t *testing.T) {
	c := newConversation(otrV3{}, fixtureRand())
	c.smpState = smpStateExpect1{}
	m := smp1Message{g2a: big.NewInt(1)}
	_, err := m.receivedMessage(c)

	assertDeepEquals(t, err, errors.New("g2a is an invalid group element"))
}

func Test_smpStateExpect1_receiveMessage1_returnsErrorIfgenerateSMP2Fails(t *testing.T) {
	c := newConversation(otrV3{}, fixedRand([]string{"ABCD"}))
	_, _, err := smpStateExpect1{}.receiveMessage1(c, fixtureMessage1())

	assertDeepEquals(t, err, errShortRandomRead)
}

func Test_smpStateExpect2_receiveMessage2_returnsErrorIfVerifySMPReturnsError(t *testing.T) {
	c := newConversation(otrV3{}, fixtureRand())
	c.s1 = fixtureSmp1()
	c.secret = bnFromHex("ABCDE56321F9A9F8E364607C8C82DECD8E8E6209E2CB952C7E649620F5286FE3")
	_, _, err := smpStateExpect2{}.receiveMessage2(c, smp2Message{g2b: big.NewInt(1)})

	assertDeepEquals(t, err, errors.New("g2b is an invalid group element"))
}

func Test_smp2Message_receivedMessage_returnsErrorIfUnderlyingPrimitiveHasErrors(t *testing.T) {
	c := newConversation(otrV3{}, fixtureRand())
	c.smpState = smpStateExpect2{}
	c.s1 = fixtureSmp1()
	c.secret = bnFromHex("ABCDE56321F9A9F8E364607C8C82DECD8E8E6209E2CB952C7E649620F5286FE3")
	_, err := smp2Message{g2b: big.NewInt(1)}.receivedMessage(c)

	assertDeepEquals(t, err, errors.New("g2b is an invalid group element"))
}

func Test_smpStateExpect2_receiveMessage2_returnsErrorIfgenerateSMPFails(t *testing.T) {
	c := newConversation(otrV3{}, fixedRand([]string{"ABCD"}))
	c.s1 = fixtureSmp1()
	c.secret = bnFromHex("ABCDE56321F9A9F8E364607C8C82DECD8E8E6209E2CB952C7E649620F5286FE3")
	_, _, err := smpStateExpect2{}.receiveMessage2(c, fixtureMessage2())

	assertDeepEquals(t, err, errShortRandomRead)
}

func Test_smpStateExpect3_receiveMessage3_returnsErrorIfVerifySMPReturnsError(t *testing.T) {
	c := newConversation(otrV3{}, fixtureRand())
	c.secret = bnFromHex("ABCDE56321F9A9F8E364607C8C82DECD8E8E6209E2CB952C7E649620F5286FE3")
	c.s2 = fixtureSmp2()
	_, _, err := smpStateExpect3{}.receiveMessage3(c, smp3Message{pa: big.NewInt(1)})

	assertDeepEquals(t, err, errors.New("Pa is an invalid group element"))
}

func Test_smp3Message_receivedMessage_returnsErrorIfUnderlyingPrimitiveDoes(t *testing.T) {
	c := newConversation(otrV3{}, fixtureRand())
	c.smpState = smpStateExpect3{}
	c.secret = bnFromHex("ABCDE56321F9A9F8E364607C8C82DECD8E8E6209E2CB952C7E649620F5286FE3")
	c.s2 = fixtureSmp2()
	_, err := smp3Message{pa: big.NewInt(1)}.receivedMessage(c)

	assertDeepEquals(t, err, errors.New("Pa is an invalid group element"))
}

func Test_smpStateExpect3_receiveMessage3_returnsErrorIfProtocolFails(t *testing.T) {
	c := newConversation(otrV3{}, fixtureRand())
	c.secret = bnFromHex("ABCDE56321F9A9F8E364607C8C82DECD8E8E6209E2CB952C7E649620F5286FE3")
	c.s2 = fixtureSmp2()
	c.s2.b3 = sub(c.s2.b3, big.NewInt(1))
	_, _, err := smpStateExpect3{}.receiveMessage3(c, fixtureMessage3())

	assertDeepEquals(t, err, errors.New("protocol failed: x != y"))
}

func Test_smpStateExpect3_receiveMessage3_returnsErrorIfCantGenerateFinalParameters(t *testing.T) {
	c := newConversation(otrV3{}, fixedRand([]string{"ABCD"}))
	c.secret = bnFromHex("ABCDE56321F9A9F8E364607C8C82DECD8E8E6209E2CB952C7E649620F5286FE3")
	c.s2 = fixtureSmp2()
	_, _, err := smpStateExpect3{}.receiveMessage3(c, fixtureMessage3())

	assertDeepEquals(t, err, errShortRandomRead)
}

func Test_smpStateExpect4_receiveMessage4_returnsErrorIfVerifySMPReturnsError(t *testing.T) {
	c := newConversation(otrV3{}, fixtureRand())
	c.s1 = fixtureSmp1()
	c.s3 = fixtureSmp3()
	_, _, err := smpStateExpect4{}.receiveMessage4(c, smp4Message{rb: big.NewInt(1)})

	assertDeepEquals(t, err, errors.New("Rb is an invalid group element"))
}

func Test_smpStateExpect4_receiveMessage4_returnsErrorIfProtocolFails(t *testing.T) {
	c := newConversation(otrV3{}, fixtureRand())
	c.s1 = fixtureSmp1()
	c.s3 = fixtureSmp3()
	c.s3.papb = sub(c.s3.papb, big.NewInt(1))
	_, _, err := smpStateExpect4{}.receiveMessage4(c, fixtureMessage4())

	assertDeepEquals(t, err, errors.New("protocol failed: x != y"))
}

func Test_smp4Message_receivedMessage_returnsErrorIfTheUnderlyingPrimitiveDoes(t *testing.T) {
	c := newConversation(otrV3{}, fixtureRand())
	c.smpState = smpStateExpect4{}
	c.s1 = fixtureSmp1()
	c.s3 = fixtureSmp3()
	_, err := smp4Message{rb: big.NewInt(1)}.receivedMessage(c)

	assertDeepEquals(t, err, errors.New("Rb is an invalid group element"))
}

func Test_receive_returnsAnyErrorThatOccurs(t *testing.T) {
	m := smp1Message{g2a: big.NewInt(1)}
	c := newConversation(otrV3{}, fixtureRand())
	//c.secret = bnFromHex("ABCDE56321F9A9F8E364607C8C82DECD8E8E6209E2CB952C7E649620F5286FE3")
	_, err := c.receiveSMP(m)
	assertDeepEquals(t, err, errors.New("g2a is an invalid group element"))
}
