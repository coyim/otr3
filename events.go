package otr3

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
