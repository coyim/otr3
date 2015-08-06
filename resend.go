package otr3

import "time"

const resendInterval = 60 * time.Second

type retransmitFlag int

var defaultResentPrefix = []byte("[resent] ")

const (
	noRetransmit retransmitFlag = iota
	retransmitWithPrefix
	retransmitExact
)

type resendContext struct {
	lastMessage      MessagePlaintext
	mayRetransmit    retransmitFlag
	messageTransform func([]byte) []byte
}

func defaultResendMessageTransform(msg []byte) []byte {
	return append(defaultResentPrefix, msg...)
}

func (c *Conversation) resendMessageTransformer() func([]byte) []byte {
	if c.resend.messageTransform == nil {
		return defaultResendMessageTransform
	}
	return c.resend.messageTransform
}

func (c *Conversation) lastMessage(msg MessagePlaintext) {
	c.resend.lastMessage = msg
}

func (c *Conversation) updateMayRetransmitTo(f retransmitFlag) {
	c.resend.mayRetransmit = f
}

func (c *Conversation) shouldRetransmit() bool {
	return c.resend.lastMessage != nil &&
		c.resend.mayRetransmit != noRetransmit &&
		c.heartbeat.lastSent.After(time.Now().Add(-resendInterval))
}

func (c *Conversation) maybeRetransmit() (messageWithHeader, error) {
	if !c.shouldRetransmit() {
		return nil, nil
	}

	msg := c.resend.lastMessage

	if c.resend.mayRetransmit == retransmitWithPrefix {
		msg = c.resendMessageTransformer()(msg)
	}

	dataMsg, err := c.genDataMsg(msg)
	if err != nil {
		return nil, err
	}

	// It is actually safe to ignore this error, since the only possible error
	// here is a problem with generating the message header, which we already do once in genDataMsg
	toSend, _ := c.wrapMessageHeader(msgTypeData, dataMsg.serialize())
	c.updateLastSent()

	return toSend, nil

	// potentially signal message event
}
