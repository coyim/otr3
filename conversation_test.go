package otr3

import "testing"

func Test_contextSMPStateMachineStartsAtSmpExpect1(t *testing.T) {
	c := newContext(otrV3{}, fixtureRand())
	assertEquals(t, c.currentState, smpStateExpect1{})
}

func Test_contextTransitionsFromSmpExpect1ToSmpExpect3(t *testing.T) {
	m := fixtureMessage1()
	c := newContext(otrV3{}, fixtureRand())
	err := c.receive(m.tlv())

	assertEquals(t, c.currentState, smpStateExpect3{})
	assertEquals(t, err, nil)
}

func Test_contextTransitionsFromSmpExpect2ToSmpExpect4(t *testing.T) {
	m := fixtureMessage2()
	c := newContext(otrV3{}, fixtureRand())
	c.currentState = smpStateExpect2{}
	err := c.receive(m.tlv())

	assertEquals(t, c.currentState, smpStateExpect4{})
	assertEquals(t, err, nil)
}

func Test_contextTransitionsFromSmpExpect3ToSmpExpect1(t *testing.T) {
	m := fixtureMessage3()
	c := newContext(otrV3{}, fixtureRand())
	c.currentState = smpStateExpect3{}
	err := c.receive(m.tlv())

	assertEquals(t, c.currentState, smpStateExpect1{})
	assertEquals(t, err, nil)
}

func Test_contextTransitionsFromSmpExpect4ToSmpExpect1(t *testing.T) {
	m := fixtureMessage4()
	c := newContext(otrV3{}, fixtureRand())
	c.currentState = smpStateExpect4{}
	err := c.receive(m.tlv())

	assertEquals(t, c.currentState, smpStateExpect1{})
	assertEquals(t, err, nil)
}

func Test_contextUnexpectedMessageTransitionsToSmpExpected1(t *testing.T) {
	m := fixtureMessage1()

	c := newContext(otrV3{}, fixtureRand())
	c.currentState = smpStateExpect3{}
	err := c.receive(m.tlv())

	assertEquals(t, c.currentState, smpStateExpect1{})
	assertEquals(t, err, errUnexpectedMessage)
}
