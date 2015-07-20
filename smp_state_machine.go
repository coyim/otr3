package otr3

import "errors"

type smpStateExpect1 struct{}
type smpStateExpect2 struct{}
type smpStateExpect3 struct{}
type smpStateExpect4 struct{}

var errUnexpectedMessage = errors.New("unexpected SMP message")

type smpMessage interface {
	receivedMessage(smpState) (smpState, error)
}

type smpState interface {
	receiveMessage1(smpMessage1) (smpState, error)
	receiveMessage2(smpMessage2) (smpState, error)
	receiveMessage3(smpMessage3) (smpState, error)
	receiveMessage4(smpMessage4) (smpState, error)
}

func (smpStateExpect1) receiveMessage1(m smpMessage1) (smpState, error) {
	return smpStateExpect3{}, nil
}

func (smpStateExpect2) receiveMessage1(m smpMessage1) (smpState, error) {
	return nil, errUnexpectedMessage
}

func (smpStateExpect3) receiveMessage1(m smpMessage1) (smpState, error) {
	return nil, errUnexpectedMessage
}

func (smpStateExpect4) receiveMessage1(m smpMessage1) (smpState, error) {
	return nil, errUnexpectedMessage
}

func (smpStateExpect1) receiveMessage2(m smpMessage2) (smpState, error) {
	return nil, errUnexpectedMessage
}

func (smpStateExpect2) receiveMessage2(m smpMessage2) (smpState, error) {
	return smpStateExpect4{}, nil
}

func (smpStateExpect3) receiveMessage2(m smpMessage2) (smpState, error) {
	return nil, errUnexpectedMessage
}

func (smpStateExpect4) receiveMessage2(m smpMessage2) (smpState, error) {
	return nil, errUnexpectedMessage
}

func (smpStateExpect1) receiveMessage3(m smpMessage3) (smpState, error) {
	return nil, errUnexpectedMessage
}

func (smpStateExpect2) receiveMessage3(m smpMessage3) (smpState, error) {
	return nil, errUnexpectedMessage
}

func (smpStateExpect3) receiveMessage3(m smpMessage3) (smpState, error) {
	return smpStateExpect1{}, nil
}

func (smpStateExpect4) receiveMessage3(m smpMessage3) (smpState, error) {
	return nil, errUnexpectedMessage
}

func (smpStateExpect1) receiveMessage4(m smpMessage4) (smpState, error) {
	return nil, errUnexpectedMessage
}

func (smpStateExpect2) receiveMessage4(m smpMessage4) (smpState, error) {
	return nil, errUnexpectedMessage
}

func (smpStateExpect3) receiveMessage4(m smpMessage4) (smpState, error) {
	return nil, errUnexpectedMessage
}

func (smpStateExpect4) receiveMessage4(m smpMessage4) (smpState, error) {
	return smpStateExpect1{}, nil
}

func (m smpMessage1) receivedMessage(currentState smpState) (s smpState, err error) {
	if s, err = currentState.receiveMessage1(m); err == errUnexpectedMessage {
		s = smpStateExpect1{}
	}
	return
}

func (m smpMessage2) receivedMessage(currentState smpState) (s smpState, err error) {
	if s, err = currentState.receiveMessage2(m); err == errUnexpectedMessage {
		s = smpStateExpect1{}
	}
	return
}

func (m smpMessage3) receivedMessage(currentState smpState) (s smpState, err error) {
	if s, err = currentState.receiveMessage3(m); err == errUnexpectedMessage {
		s = smpStateExpect1{}
	}
	return
}

func (m smpMessage4) receivedMessage(currentState smpState) (s smpState, err error) {
	if s, err = currentState.receiveMessage4(m); err == errUnexpectedMessage {
		s = smpStateExpect1{}
	}
	return
}
