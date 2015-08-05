package otr3

const maxChannelBufferSize = 2
const maxPlainChannelSize = 10

func (c *Conversation) initChannels() {
	c.receiveChan = make(chan ValidMessage, maxChannelBufferSize)
	c.sendChan = make(chan ValidMessage, maxChannelBufferSize)
	c.toSendChan = make(chan ValidMessage, maxChannelBufferSize)
	c.plainChan = make(chan []byte, maxPlainChannelSize)
}

func (c *Conversation) serve() {
	for {
		msg := <-c.receiveChan
		plain, toSend, _ := c.Receive(msg)
		if len(toSend) == 0 {
			c.toSendChan <- ValidMessage{}
		}
		for i := range toSend {
			c.toSendChan <- toSend[i]
		}
		c.plainChan <- plain
	}
	for {
		msg := <-c.sendChan
		go func() {
			toSend, _ := c.Send(msg)
			if len(toSend) == 0 {
				c.toSendChan <- ValidMessage{}
			}
			for i := range toSend {
				c.toSendChan <- toSend[i]
			}
		}()
	}
}
