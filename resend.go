package otr3

import (
	"sync"
	"time"
)

const resendInterval = 60 * time.Second

type retransmitFlag int

var defaultResentPrefix = []byte("[resent] ")

const (
	noRetransmit retransmitFlag = iota
	retransmitWithPrefix
	retransmitExact
)

type messageToResend struct {
	m      MessagePlaintext
	opaque []interface{}
}

type resendContext struct {
	mayRetransmit    retransmitFlag
	messageTransform func([]byte) []byte

	messages struct {
		m []messageToResend
		sync.RWMutex
	}
}

func (r *resendContext) later(msg MessagePlaintext, opaque ...interface{}) {
	r.messages.Lock()
	defer r.messages.Unlock()

	if r.messages.m == nil {
		r.messages.m = make([]messageToResend, 0, 5)
	}

	r.messages.m = append(r.messages.m, messageToResend{msg, opaque})
}

func (r *resendContext) pending() []messageToResend {
	r.messages.RLock()
	defer r.messages.RUnlock()

	ret := make([]messageToResend, len(r.messages.m))
	copy(ret, r.messages.m)

	return ret
}

func (r *resendContext) clear() {
	r.messages.Lock()
	defer r.messages.Unlock()

	r.messages.m = nil
}

func (r *resendContext) shouldRetransmit() bool {
	return len(r.messages.m) > 0 && r.mayRetransmit != noRetransmit
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

func (c *Conversation) lastMessage(msg MessagePlaintext, opaque ...interface{}) {
	c.resend.later(msg, opaque...)
}

func (c *Conversation) updateMayRetransmitTo(f retransmitFlag) {
	c.resend.mayRetransmit = f
}

func (c *Conversation) shouldRetransmit() bool {
	return c.resend.shouldRetransmit() &&
		c.heartbeat.lastSent.After(time.Now().Add(-resendInterval))
}

func (c *Conversation) maybeRetransmit() ([]messageWithHeader, error) {
	if !c.shouldRetransmit() {
		return nil, nil
	}

	return c.retransmit()
}

func (c *Conversation) retransmit() ([]messageWithHeader, error) {
	msgs := c.resend.pending()
	c.resend.clear()
	ret := make([]messageWithHeader, 0, len(msgs))

	resending := c.resend.mayRetransmit == retransmitWithPrefix

	for _, msgx := range msgs {
		msg := msgx.m
		if resending {
			msg = c.resendMessageTransformer()(msg)
		}
		dataMsg, _, err := c.genDataMsg(msg)
		if err != nil {
			return nil, err
		}

		// It is actually safe to ignore this error, since the only possible error
		// here is a problem with generating the instance tags for the message header,
		// which we already do once in genDataMsg
		toSend, _ := c.wrapMessageHeader(msgTypeData, dataMsg.serialize(c.version))
		ret = append(ret, toSend)
	}

	if resending {
		for _, msgx := range msgs {
			v := []interface{}{msgx.m}
			v = append(v, msgx.opaque...)
			c.messageEvent(MessageEventMessageResent, v...)
		}
	}

	c.updateLastSent()

	return ret, nil
}
