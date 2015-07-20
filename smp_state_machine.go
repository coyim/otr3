package otr3

import "errors"

type smpStateExpect1 struct{}
type smpStateExpect2 struct{}
type smpStateExpect3 struct{}
type smpStateExpect4 struct{}

var errUnexpectedMessage = errors.New("unexpected SMP message")

type smpMessage interface {
	receivedMessage(smpState) (smpState, smpMessage)
	tlv() []byte
}

type smpState interface {
	receiveMessage1(smpMessage1) (smpState, smpMessage)
	receiveMessage2(smpMessage2) (smpState, smpMessage)
	receiveMessage3(smpMessage3) (smpState, smpMessage)
	receiveMessage4(smpMessage4) (smpState, smpMessage)
	receiveAbortMessage(smpMessageAbort) (smpState, smpMessage)
}

func (smpStateExpect1) receiveMessage1(m smpMessage1) (smpState, smpMessage) {
	return smpStateExpect3{}, nil
}

func (smpStateExpect2) receiveMessage1(m smpMessage1) (smpState, smpMessage) {
	return smpStateExpect1{}, smpMessageAbort{}
}

func (smpStateExpect3) receiveMessage1(m smpMessage1) (smpState, smpMessage) {
	return smpStateExpect1{}, smpMessageAbort{}
}

func (smpStateExpect4) receiveMessage1(m smpMessage1) (smpState, smpMessage) {
	return smpStateExpect1{}, smpMessageAbort{}
}

func (smpStateExpect1) receiveMessage2(m smpMessage2) (smpState, smpMessage) {
	return smpStateExpect1{}, smpMessageAbort{}
}

func (smpStateExpect2) receiveMessage2(m smpMessage2) (smpState, smpMessage) {
	return smpStateExpect4{}, nil
}

func (smpStateExpect3) receiveMessage2(m smpMessage2) (smpState, smpMessage) {
	return smpStateExpect1{}, smpMessageAbort{}
}

func (smpStateExpect4) receiveMessage2(m smpMessage2) (smpState, smpMessage) {
	return smpStateExpect1{}, smpMessageAbort{}
}

func (smpStateExpect1) receiveMessage3(m smpMessage3) (smpState, smpMessage) {
	return smpStateExpect1{}, smpMessageAbort{}
}

func (smpStateExpect2) receiveMessage3(m smpMessage3) (smpState, smpMessage) {
	return smpStateExpect1{}, smpMessageAbort{}
}

func (smpStateExpect3) receiveMessage3(m smpMessage3) (smpState, smpMessage) {
	return smpStateExpect1{}, nil
}

func (smpStateExpect4) receiveMessage3(m smpMessage3) (smpState, smpMessage) {
	return smpStateExpect1{}, smpMessageAbort{}
}

func (smpStateExpect1) receiveMessage4(m smpMessage4) (smpState, smpMessage) {
	return smpStateExpect1{}, smpMessageAbort{}
}

func (smpStateExpect2) receiveMessage4(m smpMessage4) (smpState, smpMessage) {
	return smpStateExpect1{}, smpMessageAbort{}
}

func (smpStateExpect3) receiveMessage4(m smpMessage4) (smpState, smpMessage) {
	return smpStateExpect1{}, smpMessageAbort{}
}

func (smpStateExpect4) receiveMessage4(m smpMessage4) (smpState, smpMessage) {
	return smpStateExpect1{}, nil
}

func (smpStateExpect1) receiveAbortMessage(m smpMessageAbort) (smpState, smpMessage) {
	return smpStateExpect1{}, nil
}

func (smpStateExpect2) receiveAbortMessage(m smpMessageAbort) (smpState, smpMessage) {
	return smpStateExpect1{}, nil
}

func (smpStateExpect3) receiveAbortMessage(m smpMessageAbort) (smpState, smpMessage) {
	return smpStateExpect1{}, nil
}

func (smpStateExpect4) receiveAbortMessage(m smpMessageAbort) (smpState, smpMessage) {
	return smpStateExpect1{}, nil
}

func (m smpMessage1) receivedMessage(currentState smpState) (s smpState, toSend smpMessage) {
	return currentState.receiveMessage1(m)
}

func (m smpMessage2) receivedMessage(currentState smpState) (s smpState, toSend smpMessage) {
	return currentState.receiveMessage2(m)
}

func (m smpMessage3) receivedMessage(currentState smpState) (s smpState, toSend smpMessage) {
	return currentState.receiveMessage3(m)
}

func (m smpMessage4) receivedMessage(currentState smpState) (s smpState, toSend smpMessage) {
	return currentState.receiveMessage4(m)
}

func (m smpMessageAbort) receivedMessage(currentState smpState) (s smpState, toSend smpMessage) {
	return currentState.receiveAbortMessage(m)
}

func (smpStateExpect1) String() string { return "SMPSTATE_EXPECT1" }
func (smpStateExpect2) String() string { return "SMPSTATE_EXPECT2" }
func (smpStateExpect3) String() string { return "SMPSTATE_EXPECT3" }
