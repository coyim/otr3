package otr3

import "testing"

func Test_smpStateExpect1_goToExpectState3WhenReceivesSmpMessage1(t *testing.T) {
	state := smpStateExpect1{}
	nextState, _ := state.receiveMessage1(smpMessage1{})

	assertEquals(t, nextState, smpStateExpect3{})
}

func Test_smpStateExpect1_returnsSmpMessageAbortIfReceivesUnexpectedMessage(t *testing.T) {
	state := smpStateExpect1{}
	_, msg := state.receiveMessage2(smpMessage2{})
	assertDeepEquals(t, msg, smpMessageAbort{})

	_, msg = state.receiveMessage3(smpMessage3{})
	assertDeepEquals(t, msg, smpMessageAbort{})

	_, msg = state.receiveMessage4(smpMessage4{})
	assertDeepEquals(t, msg, smpMessageAbort{})
}

func Test_smpStateExpect2_goToExpectState4WhenReceivesSmpMessage2(t *testing.T) {
	state := smpStateExpect2{}
	nextState, _ := state.receiveMessage2(smpMessage2{})

	assertEquals(t, nextState, smpStateExpect4{})
}

func Test_smpStateExpect2_returnsSmpMessageAbortIfReceivesUnexpectedMessage(t *testing.T) {
	state := smpStateExpect2{}
	_, msg := state.receiveMessage1(smpMessage1{})
	assertDeepEquals(t, msg, smpMessageAbort{})

	_, msg = state.receiveMessage3(smpMessage3{})
	assertDeepEquals(t, msg, smpMessageAbort{})

	_, msg = state.receiveMessage4(smpMessage4{})
	assertDeepEquals(t, msg, smpMessageAbort{})
}

func Test_smpStateExpect3_goToExpectState1WhenReceivesSmpMessage3(t *testing.T) {
	state := smpStateExpect3{}
	nextState, _ := state.receiveMessage3(smpMessage3{})

	assertEquals(t, nextState, smpStateExpect1{})
}

func Test_smpStateExpect3_returnsSmpMessageAbortIfReceivesUnexpectedMessage(t *testing.T) {
	state := smpStateExpect3{}
	_, msg := state.receiveMessage1(smpMessage1{})
	assertDeepEquals(t, msg, smpMessageAbort{})

	_, msg = state.receiveMessage2(smpMessage2{})
	assertDeepEquals(t, msg, smpMessageAbort{})

	_, msg = state.receiveMessage4(smpMessage4{})
	assertDeepEquals(t, msg, smpMessageAbort{})
}

func Test_smpStateExpect4_goToExpectState1WhenReceivesSmpMessage4(t *testing.T) {
	state := smpStateExpect4{}
	nextState, _ := state.receiveMessage4(smpMessage4{})

	assertEquals(t, nextState, smpStateExpect1{})
}

func Test_smpStateExpect4_returnsSmpMessageAbortIfReceivesUnexpectedMessage(t *testing.T) {
	state := smpStateExpect4{}
	_, msg := state.receiveMessage1(smpMessage1{})
	assertDeepEquals(t, msg, smpMessageAbort{})

	_, msg = state.receiveMessage2(smpMessage2{})
	assertDeepEquals(t, msg, smpMessageAbort{})

	_, msg = state.receiveMessage3(smpMessage3{})
	assertDeepEquals(t, msg, smpMessageAbort{})
}
