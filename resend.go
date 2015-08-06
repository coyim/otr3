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

// we want to call maybe_retransmit after receiving a reveal sig or a sig message

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

// TODO: errors
func (c *Conversation) maybeRetransmit() messageWithHeader {
	if !c.shouldRetransmit() {
		return nil
	}

	msg := c.resend.lastMessage

	if c.resend.mayRetransmit == retransmitWithPrefix {
		msg = c.resendMessageTransformer()(msg)
	}

	dataMsg, err1 := c.genDataMsgWithFlag(msg, messageFlagNormal)
	if err1 != nil {
		panic(err1)
	}

	toSend, err2 := c.wrapMessageHeader(msgTypeData, dataMsg.serialize())
	if err2 != nil {
		panic(err2)
	}
	c.updateLastSent()

	return toSend

	// potentially signal message event
}
