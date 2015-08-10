package otr3

// ErrorCode represents an error that can happen during OTR processing
type ErrorCode int

const (
	// ErrorCodeEncryptionError means an error occured while encrypting a message
	ErrorCodeEncryptionError ErrorCode = iota

	// ErrorCodeMessageUnreadable means we received an unreadable encrypted message
	ErrorCodeMessageUnreadable

	// ErrorCodeMessageMalformed means the message sent is malformed
	ErrorCodeMessageMalformed
)

// SMPEvent define the events used to indicate status of SMP to the UI
type SMPEvent int

const (
	// SMPEventError means abort the current auth and update the auth progress dialog with progress_percent. This event is only sent when we receive a message for another message state than we are in
	SMPEventError SMPEvent = iota
	// SMPEventAbort means update the auth progress dialog with progress_percent
	SMPEventAbort
	// SMPEventCheated means abort the current auth and update the auth progress dialog with progress_percent
	SMPEventCheated
	// SMPEventAskForAnswer means ask the user to answer the secret question
	SMPEventAskForAnswer
	// SMPEventAskForSecret means prompt the user to enter a shared secret
	SMPEventAskForSecret
	// SMPEventInProgress means update the auth progress dialog with progress_percent
	SMPEventInProgress
	// SMPEventSuccess means update the auth progress dialog with progress_percent
	SMPEventSuccess
	// SMPEventFailure means update the auth progress dialog with progress_percent
	SMPEventFailure
)

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

// EventHandler contains the configuration necessary to be able to communicate events to the client
type EventHandler interface {
	// WishToHandleErrorMessage returns true if a valid implementation of HandleErrorMessage is available
	WishToHandleErrorMessage() bool
	// HandleErrorMessage should return a string according to the error event. This string will be concatenated to an OTR header to produce an OTR protocol error message
	HandleErrorMessage(error ErrorCode) []byte
	// HandleSMPEvent should update the authentication UI with respect to SMP events
	HandleSMPEvent(event SMPEvent, progressPercent int, question string)
	// HandleMessageEvent should handle and send the appropriate message(s) to the sender/recipient depending on the message events
	HandleMessageEvent(event MessageEvent, message []byte, err error)
}

type dynamicEventHandler struct {
	wishToHandleErrorMessage func() bool
	handleErrorMessage       func(error ErrorCode) []byte
	handleSMPEvent           func(event SMPEvent, progressPercent int, question string)
	handleMessageEvent       func(event MessageEvent, message []byte, err error)
}

func (d dynamicEventHandler) WishToHandleErrorMessage() bool {
	return d.wishToHandleErrorMessage()
}

func (d dynamicEventHandler) HandleErrorMessage(error ErrorCode) []byte {
	return d.handleErrorMessage(error)
}

func (d dynamicEventHandler) HandleSMPEvent(event SMPEvent, progressPercent int, question string) {
	d.handleSMPEvent(event, progressPercent, question)
}

func (d dynamicEventHandler) HandleMessageEvent(event MessageEvent, message []byte, err error) {
	d.handleMessageEvent(event, message, err)
}

func emptyWishToHandleErrorMessages() bool {
	return false
}

func emptyErrorMessageHandler(ErrorCode) []byte {
	return nil
}

func emptySMPEventHandler(SMPEvent, int, string) {
}

func emptyMessageEventHandler(MessageEvent, []byte, error) {
}

func emptyEventHandler() dynamicEventHandler {
	return dynamicEventHandler{
		emptyWishToHandleErrorMessages,
		emptyErrorMessageHandler,
		emptySMPEventHandler,
		emptyMessageEventHandler,
	}
}

func emptyEventHandlerWith(
	wishToHandle func() bool,
	handleErrors func(ErrorCode) []byte,
	handleSMP func(SMPEvent, int, string),
	handleEvent func(MessageEvent, []byte, error),
) EventHandler {
	e := emptyEventHandler()
	if wishToHandle != nil {
		e.wishToHandleErrorMessage = wishToHandle
	}
	if handleErrors != nil {
		e.handleErrorMessage = handleErrors
	}
	if handleSMP != nil {
		e.handleSMPEvent = handleSMP
	}
	if handleEvent != nil {
		e.handleMessageEvent = handleEvent
	}
	return e
}

func (c *Conversation) SetEventHandler(h EventHandler) {
	c.eventHandler = h
}

func (c *Conversation) setEmptyEventHandler() {
	c.SetEventHandler(emptyEventHandler())
}

func (c *Conversation) getEventHandler() EventHandler {
	if c.eventHandler == nil {
		c.setEmptyEventHandler()
	}
	return c.eventHandler
}

func (c *Conversation) generatePotentialErrorMessage(ec ErrorCode) {
	if c.getEventHandler().WishToHandleErrorMessage() {
		msg := c.getEventHandler().HandleErrorMessage(ec)
		c.injectMessage(append(append(errorMarker, ' '), msg...))
	}
}

func (c *Conversation) smpEvent(e SMPEvent, percent int) {
	c.getEventHandler().HandleSMPEvent(e, percent, "")
}

func (c *Conversation) smpEventWithQuestion(e SMPEvent, percent int, question string) {
	c.getEventHandler().HandleSMPEvent(e, percent, question)
}

func (c *Conversation) messageEvent(e MessageEvent) {
	c.getEventHandler().HandleMessageEvent(e, nil, nil)
}

func (c *Conversation) messageEventWithError(e MessageEvent, err error) {
	c.getEventHandler().HandleMessageEvent(e, nil, err)
}

func (c *Conversation) messageEventWithMessage(e MessageEvent, msg []byte) {
	c.getEventHandler().HandleMessageEvent(e, msg, nil)
}
