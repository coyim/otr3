package compat

import (
	"bytes"
	"crypto/sha1"
	"io"

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
	// NoChange happened in the security status
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

// Conversation represents a relation with a peer.
type Conversation struct {
	otr3.Conversation
	TheirPublicKey PublicKey
	PrivateKey     *PrivateKey
	SSID           [8]byte
	FragmentSize   int

	eventHandler
	initialized bool
}

type eventHandler struct {
	smpQuestion    string
	securityChange SecurityChange
}

func (eventHandler) WishToHandleErrorMessage() bool {
	return true
}

func (eventHandler) HandleErrorMessage(error otr3.ErrorCode) []byte {
	return nil
}

func (e *eventHandler) HandleSMPEvent(event otr3.SMPEvent, progressPercent int, question string) {
	switch event {
	case otr3.SMPEventAskForSecret, otr3.SMPEventAskForAnswer:
		//Why do we have both otr3.SMPEventAskForAnswer and SMPQuestion()?
		//When should each one be used?
		e.securityChange = SMPSecretNeeded
		e.smpQuestion = question
	case otr3.SMPEventSuccess:
		if progressPercent == 100 {
			e.securityChange = SMPComplete
		}
	case otr3.SMPEventFailure:
		e.securityChange = SMPFailed
	}
}

func (e *eventHandler) HandleMessageEvent(event otr3.MessageEvent, message []byte, err error) {
	if event == otr3.MessageEventConnectionEnded {
		e.securityChange = ConversationEnded
	}
}

func (e *eventHandler) consumeSecurityChange() SecurityChange {
	ret := e.securityChange
	e.securityChange = NoChange
	return ret
}

// SMPQuestion returns the human readable challenge question from the peer.
// It's only valid after Receive has returned SMPSecretNeeded.
func (c *Conversation) SMPQuestion() string {
	return c.eventHandler.smpQuestion
}

func (c *Conversation) compatInit() {
	if c.initialized {
		return
	}

	c.Conversation.Policies.AllowV2()
	c.SetEventHandler(&c.eventHandler)

	c.initialized = true
}

func (c *Conversation) updateValues() {
	if c.Conversation.GetTheirKey() != nil {
		c.TheirPublicKey.PublicKey = *c.Conversation.GetTheirKey()
	}

	c.Conversation.SetKeys(&c.PrivateKey.PrivateKey, &c.TheirPublicKey.PublicKey)

	var z [8]byte
	if bytes.Equal(c.SSID[:], z[:]) {
		c.SSID = c.GetSSID()
	}
}

// Receive handles a message from a peer. It returns a human readable message,
// an indicator of whether that message was encrypted, a hint about the
// encryption state and zero or more messages to send back to the peer.
// These messages do not need to be passed to Send before transmission.
func (c *Conversation) Receive(in []byte) (out []byte, encrypted bool, change SecurityChange, toSend [][]byte, err error) {
	c.compatInit()

	var ret []otr3.ValidMessage
	wasEncrypted := c.IsEncrypted()
	out, ret, err = c.Conversation.Receive(in)
	encrypted = c.IsEncrypted()

	if ret != nil {
		toSend = otr3.Bytes(ret)
	}

	switch {
	// There is no MessageEvent to notify the AKE completion
	// It misses the case: when the keys are
	// renegotiated within an encrypted conversation.
	case wasEncrypted == false && encrypted == true:
		change = NewKeys
	default:
		change = c.eventHandler.consumeSecurityChange()
	}

	c.updateValues()
	return
}

// Send takes a human readable message from the local user, possibly encrypts
// it and returns zero one or more messages to send to the peer.
func (c *Conversation) Send(in []byte) (toSend [][]byte, err error) {
	c.compatInit()

	var ret []otr3.ValidMessage
	ret, err = c.Conversation.Send(in)

	if ret != nil {
		toSend = otr3.Bytes(ret)
	}

	c.updateValues()
	return
}

// End ends a secure conversation by generating a termination message for
// the peer and switches to unencrypted communication.
func (c *Conversation) End() (toSend [][]byte) {
	c.compatInit()

	var ret []otr3.ValidMessage
	ret, _ = c.Conversation.End()

	if ret != nil {
		toSend = otr3.Bytes(ret)
	}

	c.updateValues()
	return
}

// Authenticate begins an authentication with the peer. Authentication involves
// an optional challenge message and a shared secret. The authentication
// proceeds until either Receive returns SMPComplete, SMPSecretNeeded (which
// indicates that a new authentication is happening and thus this one was
// aborted) or SMPFailed.
func (c *Conversation) Authenticate(question string, mutualSecret []byte) (toSend [][]byte, err error) {
	c.compatInit()
	ret, err := c.Conversation.Authenticate(question, mutualSecret)

	c.updateValues()
	return otr3.Bytes(ret), err
}

// PublicKey represents an OTR Public Key
type PublicKey struct {
	otr3.PublicKey
}

// PrivateKey represents an OTR Private Key
type PrivateKey struct {
	otr3.PrivateKey
}

// Generate will generate a new Private Key using the provided randomness
func (priv *PrivateKey) Generate(rand io.Reader) {
	if err := priv.PrivateKey.Generate(rand); err != nil {
		panic(err.Error())
	}
}

// Serialize will serialize the private key
func (priv *PrivateKey) Serialize(in []byte) []byte {
	return append(in, priv.PrivateKey.Serialize()...)
}

// Fingerprint will generate a new SHA-1 fingerprint of the serialization of the public key
func (priv *PrivateKey) Fingerprint() []byte {
	return priv.PublicKey.Fingerprint(sha1.New())
}

// Fingerprint will generate a new SHA-1 fingerprint of the serialization of the public key
func (pub *PublicKey) Fingerprint() []byte {
	return pub.PublicKey.Fingerprint(sha1.New())
}
