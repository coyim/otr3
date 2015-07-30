package compat

import (
	"io"

	"github.com/twstrike/otr3"
)

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

type PublicKey struct {
	otr3.PublicKey
}
type PrivateKey struct {
	otr3.PrivateKey
}

func (priv *PrivateKey) Generate(rand io.Reader) {
	if err := priv.PrivateKey.Generate(rand); err != nil {
		//TODO: this is not handled in xmpp, and is treated as panic in old version
		panic(err.Error())
	}
}
