package otr3

import "testing"

func Test_MessageEvent_hasValidStringImplementation(t *testing.T) {
	assertEquals(t, MessageEventEncryptionRequired.String(), "MessageEventEncryptionRequired")
	assertEquals(t, MessageEventEncryptionError.String(), "MessageEventEncryptionError")
	assertEquals(t, MessageEventConnectionEnded.String(), "MessageEventConnectionEnded")
	assertEquals(t, MessageEventSetupError.String(), "MessageEventSetupError")
	assertEquals(t, MessageEventMessageReflected.String(), "MessageEventMessageReflected")
	assertEquals(t, MessageEventMessageResent.String(), "MessageEventMessageResent")
	assertEquals(t, MessageEventReceivedMessageNotInPrivate.String(), "MessageEventReceivedMessageNotInPrivate")
	assertEquals(t, MessageEventReceivedMessageUnreadable.String(), "MessageEventReceivedMessageUnreadable")
	assertEquals(t, MessageEventReceivedMessageMalformed.String(), "MessageEventReceivedMessageMalformed")
	assertEquals(t, MessageEventLogHeartbeatReceived.String(), "MessageEventLogHeartbeatReceived")
	assertEquals(t, MessageEventLogHeartbeatSent.String(), "MessageEventLogHeartbeatSent")
	assertEquals(t, MessageEventReceivedMessageGeneralError.String(), "MessageEventReceivedMessageGeneralError")
	assertEquals(t, MessageEventReceivedMessageUnencrypted.String(), "MessageEventReceivedMessageUnencrypted")
	assertEquals(t, MessageEventReceivedMessageUnrecognized.String(), "MessageEventReceivedMessageUnrecognized")
	assertEquals(t, MessageEventReceivedMessageForOtherInstance.String(), "MessageEventReceivedMessageForOtherInstance")
	assertEquals(t, MessageEvent(20000).String(), "MESSAGE EVENT: (THIS SHOULD NEVER HAPPEN)")
}
