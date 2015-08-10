package otr3

// MessageEvent define the events used to indicate the messages that need to be sent
type MessageEvent int

const (
	// MessageEventEncryptionRequired is signaled when our policy requires encryption bt we are trying to send an unencrypted message.
	MessageEventEncryptionRequired MessageEvent = iota

	// MessageEventEncryptionError is signaled when an error occured while encrypting a message and the message was not sent.
	MessageEventEncryptionError

	// MessageEventConnectionEnded is signaled when we are asked to send a message but the peer has ended the private conversation.
	// At this point the connection should be closed or refreshed.
	MessageEventConnectionEnded

	// MessageEventSetupError will be signaled when a private conversation could not be established. The reason for this will be communicated with the attached error instance.
	MessageEventSetupError

	// MessageEventMessageReflected will be signaled if we received our own OTR messages.
	MessageEventMessageReflected

	// MessageEventMessageResent is signaled when a message is resent
	MessageEventMessageResent

	// MessageEventReceivedMessageNotInPrivate will be signaled when we receive an encrypted message that we cannot read, because we don't have an established private connection
	MessageEventReceivedMessageNotInPrivate

	// MessageEventReceivedMessageUnreadable will be signaled when we cannot read the received message.
	MessageEventReceivedMessageUnreadable

	// MessageEventReceivedMessageMalformed is signaled when we receive a message that contains malformed data.
	MessageEventReceivedMessageMalformed

	// MessageEventLogHeartbeatReceived is triggered when we received a heartbeat.
	MessageEventLogHeartbeatReceived

	// MessageEventLogHeartbeatSent is triggered when we have sent a heartbeat.
	MessageEventLogHeartbeatSent

	// MessageEventReceivedMessageGeneralError will be signaled when we receive an OTR error from the peer.
	// The message parameter will be passed, containing the error message
	MessageEventReceivedMessageGeneralError

	// MessageEventReceivedMessageUnencrypted is triggered when we receive a message that was sent in the clear when it should have been encrypted.
	// The actual message received will also be passed.
	MessageEventReceivedMessageUnencrypted

	// MessageEventReceivedMessageUnrecognized is triggered when we receive an OTR message whose type we cannot recognize
	MessageEventReceivedMessageUnrecognized

	// MessageEventReceivedMessageForOtherInstance is triggered when we receive and discard a message for another instance
	MessageEventReceivedMessageForOtherInstance
)

func (c *Conversation) messageEvent(e MessageEvent) {
	c.getEventHandler().HandleMessageEvent(e, nil, nil)
}

func (c *Conversation) messageEventWithError(e MessageEvent, err error) {
	c.getEventHandler().HandleMessageEvent(e, nil, err)
}

func (c *Conversation) messageEventWithMessage(e MessageEvent, msg []byte) {
	c.getEventHandler().HandleMessageEvent(e, msg, nil)
}
