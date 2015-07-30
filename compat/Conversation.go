package compat

import "github.com/twstrike/otr3"

type Conversation struct {
	otr3.Conversation
	TheirPublicKey otr3.PublicKey
	PrivateKey     otr3.PrivateKey
	SSID           [8]byte
	FragmentSize   int
}

func (c *Conversation) End() (toSend [][]byte) {
	toSend, ok := c.Conversation.End()
	if !ok {
		panic("unreachable")
	}
	return
}
