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
 * - OTRL_MSGEVENT_ENCRYPTION_REQUIRED
 *      Our policy requires encryption but we are trying to send
 *      an unencrypted message out.
 * - OTRL_MSGEVENT_ENCRYPTION_ERROR
 *      An error occured while encrypting a message and the message
 *      was not sent.
 * - OTRL_MSGEVENT_CONNECTION_ENDED
 *      Message has not been sent because our buddy has ended the
 *      private Conversation. We should either close the connection,
 *      or refresh it.
 * - OTRL_MSGEVENT_SETUP_ERROR
 *      A private Conversation could not be set up. A gcry_error_t
 *      will be passed.
 * - OTRL_MSGEVENT_MSG_REFLECTED
 *      Received our own OTR messages.
 * - OTRL_MSGEVENT_MSG_RESENT
 *      The previous message was resent.
 * - OTRL_MSGEVENT_RCVDMSG_NOT_IN_PRIVATE
 *      Received an encrypted message but cannot read
 *      it because no private connection is established yet.
 * - OTRL_MSGEVENT_RCVDMSG_UNREADABLE
 *      Cannot read the received message.
 * - OTRL_MSGEVENT_RCVDMSG_MALFORMED
 *      The message received contains malformed data.
 * - OTRL_MSGEVENT_LOG_HEARTBEAT_SENT
 *      Sent a heartbeat.
 * - OTRL_MSGEVENT_RCVDMSG_GENERAL_ERR
 *      Received a general OTR error. The argument 'message' will
 *      also be passed and it will contain the OTR error message.
 * - OTRL_MSGEVENT_RCVDMSG_UNENCRYPTED
 *      Received an unencrypted message. The argument 'message' will
 *      also be passed and it will contain the plaintext message.
 * - OTRL_MSGEVENT_RCVDMSG_UNRECOGNIZED
 *      Cannot recognize the type of OTR message received.
 * - OTRL_MSGEVENT_RCVDMSG_FOR_OTHER_INSTANCE
 *      Received and discarded a message intended for another instance. */
const (
	MessageEventNone MessageEvent = iota
	// MessageEventEncryptionRequired MessageEvent = iota
	// MessageEventEncryptionError
	// MessageEventConnectionEnded
	// MessageEventSetupError
	// MessageEventMessageReflected
	// MessageEventMessageResent
	// MessageEventReceivedMessageNotInPrivate
	// MessageEventReceivedMessageUnreadable
	// MessageEventReceivedMessageMalformed

	// MessageEventLogHeartbeatReceived is sent when we received a heartbeat.
	MessageEventLogHeartbeatReceived

	// MessageEventLogHeartbeatSent
	// MessageEventReceivedMessageGeneralError
	// MessageEventReceivedMessageUnencrypted
	// MessageEventReceivedMessageUnrecognized
	// MessageEventReceivedMessageForOtherInstance
)

// EventHandler contains the configuration necessary to be able to communicate events to the client
type EventHandler struct {
	// Should return a string according to the error event. This string will be concatenated to an OTR header to produce an OTR protocol error message
	errorMessage func(error ErrorCode) string
	// Update the authentication UI with respect to SMP events
	handleSMPEvent func(event SMPEvent, progressPercent int, question string)
	// Handle and send the appropriate message(s) to the sender/recipient depending on the message events
	handleMessageEvent func(event MessageEvent, message string, err error)
}

func emptyErrorMessageHandler(_ ErrorCode) string {
	return ""
}

func emptySMPEventHandler(_ SMPEvent, _ int, _ string) {
}

func emptyMessageEventHandler(_ MessageEvent, _ string, _ error) {
}

func (c *Conversation) getEventHandler() *EventHandler {
	if c.eventHandler == nil {
		c.eventHandler = &EventHandler{
			emptyErrorMessageHandler,
			emptySMPEventHandler,
			emptyMessageEventHandler,
		}
	}
	return c.eventHandler
}

func smpEventCheated(c *Conversation) {
	c.getEventHandler().handleSMPEvent(SMPEventCheated, 0, "")
}

func smpEventError(c *Conversation) {
	c.getEventHandler().handleSMPEvent(SMPEventError, 0, "")
}

func smpEventAskForAnswer(c *Conversation, question string) {
	c.getEventHandler().handleSMPEvent(SMPEventAskForAnswer, 25, question)
}

func smpEventAskForSecret(c *Conversation) {
	c.getEventHandler().handleSMPEvent(SMPEventAskForSecret, 25, "")
}

func smpEventInProgress(c *Conversation) {
	c.getEventHandler().handleSMPEvent(SMPEventInProgress, 60, "")
}

func smpEventFailure(c *Conversation) {
	c.getEventHandler().handleSMPEvent(SMPEventFailure, 100, "")
}

func smpEventSuccess(c *Conversation) {
	c.getEventHandler().handleSMPEvent(SMPEventSuccess, 100, "")
}

func smpEventAbort(c *Conversation) {
	c.getEventHandler().handleSMPEvent(SMPEventAbort, 0, "")
}

func messageEventHeartbeatReceived(c *Conversation) {
	c.getEventHandler().handleMessageEvent(MessageEventLogHeartbeatReceived, "", nil)
}
