package otr3

// ErrorCode represents an error that can happen during OTR processing
type ErrorCode int

const (
// // ErrorCodeEncryptionError means an error occured while encrypting a message
// ErrorCodeEncryptionError ErrorCode = iota
// // ErrorCodeMessageNotInPrivate means we sent encrypted message to somebody who is not in a mutual OTR session
// ErrorCodeMessageNotInPrivate
// // ErrorCodeMessageUnreadable means we sent an unreadable encrypted message
// ErrorCodeMessageUnreadable
// // ErrorCodeMessageMalformed means the message sent is malformed
// ErrorCodeMessageMalformed
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

/* Handle and send the appropriate message(s) to the sender/recipient
 * depending on the message events. All the events only require an opdata,
 * the event, and the context. The message and err will be NULL except for
 * some events (see below). The possible events are:
 * - OTRL_MSGEVENT_MSG_RESENT
 *      The previous message was resent.
 * - OTRL_MSGEVENT_RCVDMSG_NOT_IN_PRIVATE
 *      Received an encrypted message but cannot read
 *      it because no private connection is established yet.
 * - OTRL_MSGEVENT_RCVDMSG_MALFORMED
 *      The message received contains malformed data.
 * - OTRL_MSGEVENT_RCVDMSG_GENERAL_ERR
 *      Received a general OTR error. The argument 'message' will
 *      also be passed and it will contain the OTR error message.
 */
const (
	// MessageEventEncryptionRequired is signaled when our policy requires encryption bt we are trying to send an unencrypted message
	MessageEventEncryptionRequired MessageEvent = iota

	// MessageEventEncryptionError is signaled when an error occured while encrypting a message and the message was not sent
	MessageEventEncryptionError

	// MessageEventConnectionEnded is signaled when we are asked to send a message but the peer has ended the private conversation. At this point the connection should be closed or refreshed
	MessageEventConnectionEnded

	// MessageEventSetupError will be signaled when a private conversation could not be established. The reason for this will be communicated with the attached error instance
	MessageEventSetupError

	// MessageEventMessageReflected will be signaled if we received our own OTR messages.
	MessageEventMessageReflected

	// MessageEventMessageResent
	// MessageEventReceivedMessageNotInPrivate

	// * - OTRL_MSGEVENT_RCVDMSG_UNREADABLE
	// *      Cannot read the received message.
	MessageEventReceivedMessageUnreadable

	// MessageEventReceivedMessageMalformed

	// MessageEventLogHeartbeatReceived is triggered when we received a heartbeat.
	MessageEventLogHeartbeatReceived

	// MessageEventLogHeartbeatSent is triggered when we have sent a heartbeat.
	MessageEventLogHeartbeatSent

	// MessageEventReceivedMessageGeneralError

	// MessageEventReceivedMessageUnencrypted is triggered when we receive a message that was sent in the clear when it should have been encrypted. The actual message received will also be passed.
	MessageEventReceivedMessageUnencrypted

	// MessageEventReceivedMessageUnrecognized is triggered when we receive an OTR message whose type we cannot recognize
	MessageEventReceivedMessageUnrecognized

	// MessageEventReceivedMessageForOtherInstance is triggered when we receive and discard a message for another instance
	MessageEventReceivedMessageForOtherInstance
)

// EventHandler contains the configuration necessary to be able to communicate events to the client
type EventHandler interface {
	// HandleErrorMessage should return a string according to the error event. This string will be concatenated to an OTR header to produce an OTR protocol error message
	HandleErrorMessage(error ErrorCode) string
	// HandleSMPEvent should update the authentication UI with respect to SMP events
	HandleSMPEvent(event SMPEvent, progressPercent int, question string)
	// HandleMessageEvent should handle and send the appropriate message(s) to the sender/recipient depending on the message events
	HandleMessageEvent(event MessageEvent, message []byte, err error)
}

type dynamicEventHandler struct {
	handleErrorMessage func(error ErrorCode) string
	handleSMPEvent     func(event SMPEvent, progressPercent int, question string)
	handleMessageEvent func(event MessageEvent, message []byte, err error)
}

func (d dynamicEventHandler) HandleErrorMessage(error ErrorCode) string {
	return d.handleErrorMessage(error)
}

func (d dynamicEventHandler) HandleSMPEvent(event SMPEvent, progressPercent int, question string) {
	d.handleSMPEvent(event, progressPercent, question)
}

func (d dynamicEventHandler) HandleMessageEvent(event MessageEvent, message []byte, err error) {
	d.handleMessageEvent(event, message, err)
}

func emptyErrorMessageHandler(_ ErrorCode) string {
	return ""
}

func emptySMPEventHandler(_ SMPEvent, _ int, _ string) {
}

func emptyMessageEventHandler(_ MessageEvent, _ []byte, _ error) {
}

func (c *Conversation) getEventHandler() EventHandler {
	if c.eventHandler == nil {
		c.eventHandler = dynamicEventHandler{
			emptyErrorMessageHandler,
			emptySMPEventHandler,
			emptyMessageEventHandler,
		}
	}
	return c.eventHandler
}

func smpEventCheated(c *Conversation) {
	c.getEventHandler().HandleSMPEvent(SMPEventCheated, 0, "")
}

func smpEventError(c *Conversation) {
	c.getEventHandler().HandleSMPEvent(SMPEventError, 0, "")
}

func smpEventAskForAnswer(c *Conversation, question string) {
	c.getEventHandler().HandleSMPEvent(SMPEventAskForAnswer, 25, question)
}

func smpEventAskForSecret(c *Conversation) {
	c.getEventHandler().HandleSMPEvent(SMPEventAskForSecret, 25, "")
}

func smpEventInProgress(c *Conversation) {
	c.getEventHandler().HandleSMPEvent(SMPEventInProgress, 60, "")
}

func smpEventFailure(c *Conversation) {
	c.getEventHandler().HandleSMPEvent(SMPEventFailure, 100, "")
}

func smpEventSuccess(c *Conversation) {
	c.getEventHandler().HandleSMPEvent(SMPEventSuccess, 100, "")
}

func smpEventAbort(c *Conversation) {
	c.getEventHandler().HandleSMPEvent(SMPEventAbort, 0, "")
}

func messageEventHeartbeatReceived(c *Conversation) {
	c.getEventHandler().HandleMessageEvent(MessageEventLogHeartbeatReceived, nil, nil)
}

func messageEventHeartbeatSent(c *Conversation) {
	c.getEventHandler().HandleMessageEvent(MessageEventLogHeartbeatSent, nil, nil)
}

func messageEventSetupError(c *Conversation, e error) {
	c.getEventHandler().HandleMessageEvent(MessageEventSetupError, nil, e)
}

func messageEventReflected(c *Conversation) {
	c.getEventHandler().HandleMessageEvent(MessageEventMessageReflected, nil, nil)
}

func messageEventEncryptionRequired(c *Conversation) {
	c.getEventHandler().HandleMessageEvent(MessageEventEncryptionRequired, nil, nil)
}

func messageEventConnectionEnded(c *Conversation) {
	c.getEventHandler().HandleMessageEvent(MessageEventConnectionEnded, nil, nil)
}

func messageEventReceivedUnencryptedMessage(c *Conversation, msg []byte) {
	c.getEventHandler().HandleMessageEvent(MessageEventReceivedMessageUnencrypted, msg, nil)
}

func messageEventReceivedUnrecognizedMessage(c *Conversation) {
	c.getEventHandler().HandleMessageEvent(MessageEventReceivedMessageUnrecognized, nil, nil)
}

func messageEventReceivedMessageForOtherInstance(c *Conversation) {
	c.getEventHandler().HandleMessageEvent(MessageEventReceivedMessageForOtherInstance, nil, nil)
}

func messageEventEncryptionError(c *Conversation) {
	c.getEventHandler().HandleMessageEvent(MessageEventEncryptionError, nil, nil)
}
