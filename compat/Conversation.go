package compat

import (
	"crypto/sha1"
	"encoding/base64"
	"io"
	"strconv"

	"github.com/twstrike/otr3"
)

// QueryMessage can be sent to a peer to start an OTR conversation.
var QueryMessage = "?OTRv2?"

// ErrorPrefix can be used to make an OTR error by appending an error message
// to it.
var ErrorPrefix = "?OTR Error:"

// SecurityChange describes a change in the security state of a Conversation.
type SecurityChange int

const (
	NoChange SecurityChange = iota
	// NewKeys indicates that a key exchange has completed. This occurs
	// when a conversation first becomes encrypted, and when the keys are
	// renegotiated within an encrypted conversation.
	NewKeys
	// SMPSecretNeeded indicates that the peer has started an
	// authentication and that we need to supply a secret. Call SMPQuestion
	// to get the optional, human readable challenge and then Authenticate
	// to supply the matching secret.
	SMPSecretNeeded
	// SMPComplete indicates that an authentication completed. The identity
	// of the peer has now been confirmed.
	SMPComplete
	// SMPFailed indicates that an authentication failed.
	SMPFailed
	// ConversationEnded indicates that the peer ended the secure
	// conversation.
	ConversationEnded
)

type Conversation struct {
	otr3.Conversation
	TheirPublicKey PublicKey
	PrivateKey     *PrivateKey
	SSID           [8]byte
	FragmentSize   int
}

func (c *Conversation) compatInit() {
	c.Conversation.Policies.AllowV2()
	c.OurKey = &c.PrivateKey.PrivateKey
	c.TheirKey = &c.TheirPublicKey.PublicKey
}

func (c *Conversation) Receive(in []byte) (out []byte, encrypted bool, change SecurityChange, toSend [][]byte, err error) {
	c.compatInit()
	encrypted = c.IsEncrypted()
	out, toSend, err = c.Conversation.Receive(in)
	return
}

func (c *Conversation) Send(in []byte) (toSend [][]byte, err error) {
	c.compatInit()
	toSend, err = c.Conversation.Send(in)
	return
}

func (c *Conversation) End() (toSend [][]byte) {
	c.compatInit()
	toSend = c.Conversation.End()
	return
}

func (c *Conversation) encode(msg []byte) [][]byte {
	msgPrefix := []byte("?OTR:")
	minFragmentSize := 18
	b64 := make([]byte, base64.StdEncoding.EncodedLen(len(msg))+len(msgPrefix)+1)
	base64.StdEncoding.Encode(b64[len(msgPrefix):], msg)
	copy(b64, msgPrefix)
	b64[len(b64)-1] = '.'

	if c.FragmentSize < minFragmentSize || len(b64) <= c.FragmentSize {
		// We can encode this in a single fragment.
		return [][]byte{b64}
	}

	// We have to fragment this message.
	var ret [][]byte
	bytesPerFragment := c.FragmentSize - minFragmentSize
	numFragments := (len(b64) + bytesPerFragment) / bytesPerFragment

	for i := 0; i < numFragments; i++ {
		frag := []byte("?OTR," + strconv.Itoa(i+1) + "," + strconv.Itoa(numFragments) + ",")
		todo := bytesPerFragment
		if todo > len(b64) {
			todo = len(b64)
		}
		frag = append(frag, b64[:todo]...)
		b64 = b64[todo:]
		frag = append(frag, ',')
		ret = append(ret, frag)
	}

	return ret
}

type PublicKey struct {
	otr3.PublicKey
}

type PrivateKey struct {
	otr3.PrivateKey
}

func (priv *PrivateKey) Generate(rand io.Reader) {
	if err := priv.PrivateKey.Generate(rand); err != nil {
		panic(err.Error())
	}
}

func (priv *PrivateKey) Serialize(in []byte) []byte {
	return append(in, priv.PrivateKey.Serialize()...)
}

func (priv *PrivateKey) Fingerprint() []byte {
	return priv.PublicKey.Fingerprint(sha1.New())
}

func (pub *PublicKey) Fingerprint() []byte {
	return pub.PublicKey.Fingerprint(sha1.New())
}
