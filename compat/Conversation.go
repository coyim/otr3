package compat

import "github.com/twstrike/otr3"

type Conversation struct {
	otr3.Conversation
	TheirPublicKey otr3.PublicKey
	PrivateKey     otr3.PrivateKey
	SSID           [8]byte
	FragmentSize   int
}
