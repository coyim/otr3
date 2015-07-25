package otr3

import "errors"

type smpStateBase struct{}
type smpStateExpect1 struct{ smpStateBase }
type smpStateExpect2 struct{ smpStateBase }
type smpStateExpect3 struct{ smpStateBase }
type smpStateExpect4 struct{ smpStateBase }

var errUnexpectedMessage = errors.New("unexpected SMP message")

type smpMessage interface {
	receivedMessage(*otrContext) (smpMessage, error)
	tlv() tlv
}

type smpState interface {
	receiveMessage1(*otrContext, smpMessage1) (smpState, smpMessage, error)
	receiveMessage2(*otrContext, smpMessage2) (smpState, smpMessage, error)
	receiveMessage3(*otrContext, smpMessage3) (smpState, smpMessage, error)
	receiveMessage4(*otrContext, smpMessage4) (smpState, smpMessage, error)
	receiveAbortMessage(*otrContext, smpMessageAbort) (smpState, smpMessage)
}

func (c *otrContext) restart() []byte {
	var ret smpMessage
	c.smpState, ret, _ = abortStateMachine()
	return ret.tlv().serialize()
}

func abortStateMachine() (smpState, smpMessage, error) {
	return abortStateMachineWith(nil)
}

func abortStateMachineWith(e error) (smpState, smpMessage, error) {
	return smpStateExpect1{}, smpMessageAbort{}, e
}

func (c *otrContext) receiveSMP(m smpMessage) ([]byte, error) {
	toSend, err := m.receivedMessage(c)

	if err != nil {
		return nil, err
	}

	if toSend == nil {
		return nil, nil
	}

	return toSend.tlv().serialize(), nil
}

func (smpStateBase) receiveMessage1(c *otrContext, m smpMessage1) (smpState, smpMessage, error) {
	return abortStateMachine()
}

func (smpStateBase) receiveMessage2(c *otrContext, m smpMessage2) (smpState, smpMessage, error) {
	return abortStateMachine()
}

func (smpStateBase) receiveMessage3(c *otrContext, m smpMessage3) (smpState, smpMessage, error) {
	return abortStateMachine()
}

func (smpStateBase) receiveMessage4(c *otrContext, m smpMessage4) (smpState, smpMessage, error) {
	return abortStateMachine()
}

func (smpStateBase) receiveAbortMessage(c *otrContext, m smpMessageAbort) (smpState, smpMessage) {
	abortStateMachine()
	return smpStateExpect1{}, nil
}

func (smpStateExpect1) receiveMessage1(c *otrContext, m smpMessage1) (smpState, smpMessage, error) {
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

func (smpStateExpect2) receiveMessage2(c *otrContext, m smpMessage2) (smpState, smpMessage, error) {
	//TODO: make sure c.s1 is stored when it is generated

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

func (smpStateExpect3) receiveMessage3(c *otrContext, m smpMessage3) (smpState, smpMessage, error) {
	//TODO: make sure c.s2 is stored when it is generated

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

func (smpStateExpect4) receiveMessage4(c *otrContext, m smpMessage4) (smpState, smpMessage, error) {
	//TODO: make sure c.s3 is stored when it is generated

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

func (m smpMessage1) receivedMessage(c *otrContext) (ret smpMessage, err error) {
	c.smpState, ret, err = c.smpState.receiveMessage1(c, m)
	return
}

func (m smpMessage2) receivedMessage(c *otrContext) (ret smpMessage, err error) {
	c.smpState, ret, err = c.smpState.receiveMessage2(c, m)
	return
}

func (m smpMessage3) receivedMessage(c *otrContext) (ret smpMessage, err error) {
	c.smpState, ret, err = c.smpState.receiveMessage3(c, m)
	return
}

func (m smpMessage4) receivedMessage(c *otrContext) (ret smpMessage, err error) {
	c.smpState, ret, err = c.smpState.receiveMessage4(c, m)
	return
}

func (m smpMessageAbort) receivedMessage(c *otrContext) (ret smpMessage, err error) {
	c.smpState, ret = c.smpState.receiveAbortMessage(c, m)
	return
}

func (smpStateExpect1) String() string { return "SMPSTATE_EXPECT1" }
func (smpStateExpect2) String() string { return "SMPSTATE_EXPECT2" }
func (smpStateExpect3) String() string { return "SMPSTATE_EXPECT3" }
