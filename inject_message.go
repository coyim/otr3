package otr3

type injections struct {
	messages []ValidMessage
}

// injectMessage will promise to send the messages now or later
func (c *Conversation) injectMessage(vm ValidMessage) {
	c.injections.messages = append(c.injections.messages, vm)
}

func (c *Conversation) withInjections(vms []ValidMessage) []ValidMessage {
	msgs := c.injections.messages
	c.injections.messages = c.injections.messages[0:0]
	return append(vms, msgs...)
}
