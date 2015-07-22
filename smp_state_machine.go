package otr3

import "errors"

type smpStateExpect1 struct{}
type smpStateExpect2 struct{}
type smpStateExpect3 struct{}
type smpStateExpect4 struct{}

var errUnexpectedMessage = errors.New("unexpected SMP message")

type smpMessage interface {
	receivedMessage(*smpContext) (smpMessage, error)
	tlv() []byte
}

type smpState interface {
	receiveMessage1(*smpContext, smpMessage1) (smpState, smpMessage, error)
	receiveMessage2(*smpContext, smpMessage2) (smpState, smpMessage, error)
	receiveMessage3(*smpContext, smpMessage3) (smpState, smpMessage, error)
	receiveMessage4(*smpContext, smpMessage4) (smpState, smpMessage, error)
	receiveAbortMessage(*smpContext, smpMessageAbort) (smpState, smpMessage)
}

func (c *smpContext) restart() []byte {
	var ret smpMessage
	c.smpState, ret, _ = abortStateMachine()
	return ret.tlv()
}

func abortStateMachine() (smpState, smpMessage, error) {
	return abortStateMachineWith(nil)
}

func abortStateMachineWith(e error) (smpState, smpMessage, error) {
	return smpStateExpect1{}, smpMessageAbort{}, e
}

func (c *smpContext) receive(m smpMessage) []byte {
	// TODO: error
	toSend, _ := m.receivedMessage(c)

	if toSend == nil {
		return nil
	}

	return toSend.tlv()
}

func (smpStateExpect1) receiveMessage1(c *smpContext, m smpMessage1) (smpState, smpMessage, error) {
	err := c.verifySMP1(m)
	if err != nil {
		return abortStateMachineWith(err)
	}

	ret, ok := c.generateSMP2(c.secret, m)
	if !ok {
		return abortStateMachineWith(errShortRandomRead)
	}

	return smpStateExpect3{}, ret.msg, nil
}

func (smpStateExpect2) receiveMessage1(c *smpContext, m smpMessage1) (smpState, smpMessage, error) {
	return abortStateMachine()
}

func (smpStateExpect3) receiveMessage1(c *smpContext, m smpMessage1) (smpState, smpMessage, error) {
	return abortStateMachine()
}

func (smpStateExpect4) receiveMessage1(c *smpContext, m smpMessage1) (smpState, smpMessage, error) {
	return abortStateMachine()
}

func (smpStateExpect1) receiveMessage2(c *smpContext, m smpMessage2) (smpState, smpMessage, error) {
	return abortStateMachine()
}

func (smpStateExpect2) receiveMessage2(c *smpContext, m smpMessage2) (smpState, smpMessage, error) {
	//TODO: make sure c.s1 is stored when it is generated
	//TODO: c.s1 could be merged into the smpContext, the same way akeContext works

	err := c.verifySMP2(c.s1, m)
	if err != nil {
		return abortStateMachineWith(err)
	}

	ret, ok := c.generateSMP3(c.secret, c.s1, m)
	if !ok {
		return abortStateMachineWith(errShortRandomRead)
	}

	return smpStateExpect4{}, ret.msg, nil
}

func (smpStateExpect3) receiveMessage2(c *smpContext, m smpMessage2) (smpState, smpMessage, error) {
	return abortStateMachine()
}

func (smpStateExpect4) receiveMessage2(c *smpContext, m smpMessage2) (smpState, smpMessage, error) {
	return abortStateMachine()
}

func (smpStateExpect1) receiveMessage3(c *smpContext, m smpMessage3) (smpState, smpMessage, error) {
	return abortStateMachine()
}

func (smpStateExpect2) receiveMessage3(c *smpContext, m smpMessage3) (smpState, smpMessage, error) {
	return abortStateMachine()
}

func (smpStateExpect3) receiveMessage3(c *smpContext, m smpMessage3) (smpState, smpMessage, error) {
	//TODO: make sure c.s2 is stored when it is generated
	//TODO: c.s2 could be merged into the smpContext, the same way akeContext works

	err := c.verifySMP3(c.s2, m)
	if err != nil {
		return abortStateMachineWith(err)
	}

	err = c.verifySMP3ProtocolSuccess(c.s2, m)
	if err != nil {
		return abortStateMachineWith(err)
	}

	ret, ok := c.generateSMP4(c.secret, c.s2, m)
	if !ok {
		return abortStateMachineWith(errShortRandomRead)
	}

	return smpStateExpect1{}, ret.msg, nil
}

func (smpStateExpect4) receiveMessage3(c *smpContext, m smpMessage3) (smpState, smpMessage, error) {
	return abortStateMachine()
}

func (smpStateExpect1) receiveMessage4(c *smpContext, m smpMessage4) (smpState, smpMessage, error) {
	return abortStateMachine()
}

func (smpStateExpect2) receiveMessage4(c *smpContext, m smpMessage4) (smpState, smpMessage, error) {
	return abortStateMachine()
}

func (smpStateExpect3) receiveMessage4(c *smpContext, m smpMessage4) (smpState, smpMessage, error) {
	return abortStateMachine()
}

func (smpStateExpect4) receiveMessage4(c *smpContext, m smpMessage4) (smpState, smpMessage, error) {
	//TODO: make sure c.s3 is stored when it is generated
	//TODO: c.s3 could be merged into the smpContext, the same way akeContext works

	err := c.verifySMP4(c.s3, m)
	if err != nil {
		return abortStateMachineWith(err)
	}

	err = c.verifySMP4ProtocolSuccess(c.s1, c.s3, m)
	if err != nil {
		return abortStateMachineWith(err)
	}

	return smpStateExpect1{}, nil, nil
}

func (smpStateExpect1) receiveAbortMessage(c *smpContext, m smpMessageAbort) (smpState, smpMessage) {
	abortStateMachine()
	return smpStateExpect1{}, nil
}

func (smpStateExpect2) receiveAbortMessage(c *smpContext, m smpMessageAbort) (smpState, smpMessage) {
	abortStateMachine()
	return smpStateExpect1{}, nil
}

func (smpStateExpect3) receiveAbortMessage(c *smpContext, m smpMessageAbort) (smpState, smpMessage) {
	abortStateMachine()
	return smpStateExpect1{}, nil
}

func (smpStateExpect4) receiveAbortMessage(c *smpContext, m smpMessageAbort) (smpState, smpMessage) {
	abortStateMachine()
	return smpStateExpect1{}, nil
}

func (m smpMessage1) receivedMessage(c *smpContext) (ret smpMessage, err error) {
	c.smpState, ret, err = c.smpState.receiveMessage1(c, m)
	return
}

func (m smpMessage2) receivedMessage(c *smpContext) (ret smpMessage, err error) {
	c.smpState, ret, err = c.smpState.receiveMessage2(c, m)
	return
}

func (m smpMessage3) receivedMessage(c *smpContext) (ret smpMessage, err error) {
	c.smpState, ret, err = c.smpState.receiveMessage3(c, m)
	return
}

func (m smpMessage4) receivedMessage(c *smpContext) (ret smpMessage, err error) {
	c.smpState, ret, err = c.smpState.receiveMessage4(c, m)
	return
}

func (m smpMessageAbort) receivedMessage(c *smpContext) (ret smpMessage, err error) {
	c.smpState, ret = c.smpState.receiveAbortMessage(c, m)
	return
}

func (smpStateExpect1) String() string { return "SMPSTATE_EXPECT1" }
func (smpStateExpect2) String() string { return "SMPSTATE_EXPECT2" }
func (smpStateExpect3) String() string { return "SMPSTATE_EXPECT3" }
