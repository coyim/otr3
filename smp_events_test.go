package otr3

import "testing"

func Test_SMPEvent_hasValidStringImplementation(t *testing.T) {
	assertEquals(t, SMPEventError.String(), "SMPEventError")
	assertEquals(t, SMPEventAbort.String(), "SMPEventAbort")
	assertEquals(t, SMPEventCheated.String(), "SMPEventCheated")
	assertEquals(t, SMPEventAskForAnswer.String(), "SMPEventAskForAnswer")
	assertEquals(t, SMPEventAskForSecret.String(), "SMPEventAskForSecret")
	assertEquals(t, SMPEventInProgress.String(), "SMPEventInProgress")
	assertEquals(t, SMPEventSuccess.String(), "SMPEventSuccess")
	assertEquals(t, SMPEventFailure.String(), "SMPEventFailure")
	assertEquals(t, SMPEvent(20000).String(), "SMP EVENT: (THIS SHOULD NEVER HAPPEN)")
}
