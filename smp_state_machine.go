package otr3

import "errors"

type smpStateExpect1 struct{}
type smpStateExpect2 struct{}
type smpStateExpect3 struct{}
type smpStateExpect4 struct{}

var unexpectedMessageError = errors.New("unexpected SMP message")

type smpMessage interface {
	receiveMessage()
}

type smpState interface {
	receiveMessage1(smpMessage1) (smpState, error)
	receiveMessage2(smpMessage2) (smpState, error)
	receiveMessage3(smpMessage3) (smpState, error)
	receiveMessage4(smpMessage4) (smpState, error)
}

func (*smpStateExpect1) receiveMessage1(m smpMessage1) (smpState, error) {
	return &smpStateExpect3{}, nil
}

func (*smpStateExpect1) receiveMessage2(m smpMessage2) (smpState, error) {
	return nil, unexpectedMessageError
}

func (*smpStateExpect1) receiveMessage3(m smpMessage3) (smpState, error) {
	return nil, unexpectedMessageError
}

func (*smpStateExpect1) receiveMessage4(m smpMessage4) (smpState, error) {
	return nil, unexpectedMessageError
}

func (*smpStateExpect2) receiveMessage1(m smpMessage1) (smpState, error) {
	return nil, unexpectedMessageError
}

func (*smpStateExpect2) receiveMessage2(m smpMessage2) (smpState, error) {
	return &smpStateExpect4{}, nil
}

func (*smpStateExpect2) receiveMessage3(m smpMessage3) (smpState, error) {
	return nil, unexpectedMessageError
}

func (*smpStateExpect2) receiveMessage4(m smpMessage4) (smpState, error) {
	return nil, unexpectedMessageError
}

func (*smpStateExpect3) receiveMessage1(m smpMessage1) (smpState, error) {
	return nil, unexpectedMessageError
}

func (*smpStateExpect3) receiveMessage2(m smpMessage2) (smpState, error) {
	return nil, unexpectedMessageError
}

func (*smpStateExpect3) receiveMessage3(m smpMessage3) (smpState, error) {
	return &smpStateExpect1{}, nil
}

func (*smpStateExpect3) receiveMessage4(m smpMessage4) (smpState, error) {
	return nil, unexpectedMessageError
}

func (*smpStateExpect4) receiveMessage1(m smpMessage1) (smpState, error) {
	return nil, unexpectedMessageError
}

func (*smpStateExpect4) receiveMessage2(m smpMessage2) (smpState, error) {
	return nil, unexpectedMessageError
}

func (*smpStateExpect4) receiveMessage3(m smpMessage3) (smpState, error) {
	return nil, unexpectedMessageError
}

func (*smpStateExpect4) receiveMessage4(m smpMessage4) (smpState, error) {
	return &smpStateExpect1{}, nil
}

func (m smpMessage1) receivedMessage(currentState smpState) {
	currentState.receiveMessage1(m)
}

func (m smpMessage2) receivedMessage(currentState smpState) {
	currentState.receiveMessage2(m)
}

func (m smpMessage3) receivedMessage(currentState smpState) {
	currentState.receiveMessage3(m)
}

func (m smpMessage4) receivedMessage(currentState smpState) {
	currentState.receiveMessage4(m)
}