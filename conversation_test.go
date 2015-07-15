package otr3

import "testing"

func Test_contextSMPStateMachineStartsAtSmpExpect1(t *testing.T) {
	c := newContext(otrV3{}, fixtureRand())
	assertEquals(t, c.smpState, smpStateExpect1{})
}

func Test_contextTransitionsFromSmpExpect1ToSmpExpect3(t *testing.T) {
	m := fixtureMessage1()
	c := newContext(otrV3{}, fixtureRand())
	err := c.receiveSMPMessage(m.tlv())

	assertEquals(t, c.smpState, smpStateExpect3{})
	assertEquals(t, err, nil)
}

func Test_contextTransitionsFromSmpExpect2ToSmpExpect4(t *testing.T) {
	m := fixtureMessage2()
	c := newContext(otrV3{}, fixtureRand())
	c.smpState = smpStateExpect2{}
	err := c.receiveSMPMessage(m.tlv())

	assertEquals(t, c.smpState, smpStateExpect4{})
	assertEquals(t, err, nil)
}

func Test_contextTransitionsFromSmpExpect3ToSmpExpect1(t *testing.T) {
	m := fixtureMessage3()
	c := newContext(otrV3{}, fixtureRand())
	c.smpState = smpStateExpect3{}
	err := c.receiveSMPMessage(m.tlv())

	assertEquals(t, c.smpState, smpStateExpect1{})
	assertEquals(t, err, nil)
}

func Test_contextTransitionsFromSmpExpect4ToSmpExpect1(t *testing.T) {
	m := fixtureMessage4()
	c := newContext(otrV3{}, fixtureRand())
	c.smpState = smpStateExpect4{}
	err := c.receiveSMPMessage(m.tlv())

	assertEquals(t, c.smpState, smpStateExpect1{})
	assertEquals(t, err, nil)
}

func Test_contextUnexpectedMessageTransitionsToSmpExpected1(t *testing.T) {
	m := fixtureMessage1()

	c := newContext(otrV3{}, fixtureRand())
	c.smpState = smpStateExpect3{}
	err := c.receiveSMPMessage(m.tlv())

	assertEquals(t, c.smpState, smpStateExpect1{})
	assertEquals(t, err, errUnexpectedMessage)
}
