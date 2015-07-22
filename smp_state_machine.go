package otr3

import "errors"

type smpStateExpect1 struct{}
type smpStateExpect2 struct{}
type smpStateExpect3 struct{}
type smpStateExpect4 struct{}

var errUnexpectedMessage = errors.New("unexpected SMP message")

type smpMessage interface {
	receivedMessage(*smpContext) smpMessage
	tlv() []byte
}

type smpState interface {
	receiveMessage1(*smpContext, smpMessage1) (smpState, smpMessage)
	receiveMessage2(*smpContext, smpMessage2) (smpState, smpMessage)
	receiveMessage3(*smpContext, smpMessage3) (smpState, smpMessage)
	receiveMessage4(*smpContext, smpMessage4) (smpState, smpMessage)
	receiveAbortMessage(*smpContext, smpMessageAbort) (smpState, smpMessage)
}

func (c *smpContext) restart() []byte {
	var ret smpMessage
	c.smpState, ret = c.abortStateMachine()
	return ret.tlv()
}

func (c *smpContext) abortStateMachine() (smpState, smpMessage) {
	//TODO clear all s1-4 variables from smpContext
	return smpStateExpect1{}, smpMessageAbort{}
}

func (c *smpContext) receive(m smpMessage) []byte {
	toSend := m.receivedMessage(c)

	if toSend == nil {
		return nil
	}

	return toSend.tlv()
}

func (smpStateExpect1) receiveMessage1(c *smpContext, m smpMessage1) (smpState, smpMessage) {
	err := c.verifySMP1(m)
	if err != nil {
		//TODO errors
		return c.abortStateMachine()
	}

	ret, ok := c.generateSMP2(c.secret, m)
	if !ok {
		//TODO error
		return c.abortStateMachine()
	}

	return smpStateExpect3{}, ret.msg
}

func (smpStateExpect2) receiveMessage1(c *smpContext, m smpMessage1) (smpState, smpMessage) {
	return c.abortStateMachine()
}

func (smpStateExpect3) receiveMessage1(c *smpContext, m smpMessage1) (smpState, smpMessage) {
	return c.abortStateMachine()
}

func (smpStateExpect4) receiveMessage1(c *smpContext, m smpMessage1) (smpState, smpMessage) {
	return c.abortStateMachine()
}

func (smpStateExpect1) receiveMessage2(c *smpContext, m smpMessage2) (smpState, smpMessage) {
	return c.abortStateMachine()
}

func (smpStateExpect2) receiveMessage2(c *smpContext, m smpMessage2) (smpState, smpMessage) {
	//TODO: make sure c.s1 is stored when it is generated
	//TODO: c.s1 could be merged into the smpContext, the same way akeContext works

	err := c.verifySMP2(c.s1, m)
	if err != nil {
		//TODO errors
		return c.abortStateMachine()
	}

	ret, ok := c.generateSMP3(c.secret, c.s1, m)
	if !ok {
		//TODO error
		return c.abortStateMachine()
	}

	return smpStateExpect4{}, ret.msg
}

func (smpStateExpect3) receiveMessage2(c *smpContext, m smpMessage2) (smpState, smpMessage) {
	return c.abortStateMachine()
}

func (smpStateExpect4) receiveMessage2(c *smpContext, m smpMessage2) (smpState, smpMessage) {
	return c.abortStateMachine()
}

func (smpStateExpect1) receiveMessage3(c *smpContext, m smpMessage3) (smpState, smpMessage) {
	return c.abortStateMachine()
}

func (smpStateExpect2) receiveMessage3(c *smpContext, m smpMessage3) (smpState, smpMessage) {
	return c.abortStateMachine()
}

func (smpStateExpect3) receiveMessage3(c *smpContext, m smpMessage3) (smpState, smpMessage) {
	//TODO: make sure c.s2 is stored when it is generated
	//TODO: c.s2 could be merged into the smpContext, the same way akeContext works

	err := c.verifySMP3(c.s2, m)
	if err != nil {
		//TODO errors
		return c.abortStateMachine()
	}

	err = c.verifySMP3ProtocolSuccess(c.s2, m)
	if err != nil {
		//TODO errors
		return c.abortStateMachine()
	}

	ret, ok := c.generateSMP4(c.secret, c.s2, m)
	if !ok {
		//TODO error
		return c.abortStateMachine()
	}

	return smpStateExpect1{}, ret.msg
}

func (smpStateExpect4) receiveMessage3(c *smpContext, m smpMessage3) (smpState, smpMessage) {
	return c.abortStateMachine()
}

func (smpStateExpect1) receiveMessage4(c *smpContext, m smpMessage4) (smpState, smpMessage) {
	return c.abortStateMachine()
}

func (smpStateExpect2) receiveMessage4(c *smpContext, m smpMessage4) (smpState, smpMessage) {
	return c.abortStateMachine()
}

func (smpStateExpect3) receiveMessage4(c *smpContext, m smpMessage4) (smpState, smpMessage) {
	return c.abortStateMachine()
}

func (smpStateExpect4) receiveMessage4(c *smpContext, m smpMessage4) (smpState, smpMessage) {
	//TODO: make sure c.s3 is stored when it is generated
	//TODO: c.s3 could be merged into the smpContext, the same way akeContext works

	err := c.verifySMP4(c.s3, m)
	if err != nil {
		//TODO errors
		return c.abortStateMachine()
	}

	err = c.verifySMP4ProtocolSuccess(c.s1, c.s3, m)
	if err != nil {
		//TODO errors
		return c.abortStateMachine()
	}

	return smpStateExpect1{}, nil
}

func (smpStateExpect1) receiveAbortMessage(c *smpContext, m smpMessageAbort) (smpState, smpMessage) {
	c.abortStateMachine()
	return smpStateExpect1{}, nil
}

func (smpStateExpect2) receiveAbortMessage(c *smpContext, m smpMessageAbort) (smpState, smpMessage) {
	c.abortStateMachine()
	return smpStateExpect1{}, nil
}

func (smpStateExpect3) receiveAbortMessage(c *smpContext, m smpMessageAbort) (smpState, smpMessage) {
	c.abortStateMachine()
	return smpStateExpect1{}, nil
}

func (smpStateExpect4) receiveAbortMessage(c *smpContext, m smpMessageAbort) (smpState, smpMessage) {
	c.abortStateMachine()
	return smpStateExpect1{}, nil
}

func (m smpMessage1) receivedMessage(c *smpContext) smpMessage {
	var ret smpMessage
	c.smpState, ret = c.smpState.receiveMessage1(c, m)
	return ret
}

func (m smpMessage2) receivedMessage(c *smpContext) smpMessage {
	var ret smpMessage
	c.smpState, ret = c.smpState.receiveMessage2(c, m)
	return ret
}

func (m smpMessage3) receivedMessage(c *smpContext) smpMessage {
	var ret smpMessage
	c.smpState, ret = c.smpState.receiveMessage3(c, m)
	return ret
}

func (m smpMessage4) receivedMessage(c *smpContext) smpMessage {
	var ret smpMessage
	c.smpState, ret = c.smpState.receiveMessage4(c, m)
	return ret
}

func (m smpMessageAbort) receivedMessage(c *smpContext) smpMessage {
	var ret smpMessage
	c.smpState, ret = c.smpState.receiveAbortMessage(c, m)
	return ret
}

func (smpStateExpect1) String() string { return "SMPSTATE_EXPECT1" }
func (smpStateExpect2) String() string { return "SMPSTATE_EXPECT2" }
func (smpStateExpect3) String() string { return "SMPSTATE_EXPECT3" }
