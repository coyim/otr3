package compat

import "github.com/twstrike/otr3"

var (
	// QueryMessage can be sent to a peer to start an OTR conversation.
	QueryMessage = "?OTRv2?"

	// ErrorPrefix can be used to make an OTR error by appending an error message
	// to it.
	ErrorPrefix = "?OTR Error:"

	minFragmentSize = 18
)

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
	smpQuestion      string
	securityChange   SecurityChange
	waitingForSecret bool
}

func (eventHandler) WishToHandleErrorMessage() bool {
	return true
}

func (eventHandler) HandleErrorMessage(error otr3.ErrorCode) []byte {
	return nil
}

func (e *eventHandler) HandleSecurityEvent(event otr3.SecurityEvent) {
	switch event {
	case otr3.GoneSecure, otr3.StillSecure:
		e.securityChange = NewKeys
	}
}

func (e *eventHandler) HandleSMPEvent(event otr3.SMPEvent, progressPercent int, question string) {
	switch event {
	case otr3.SMPEventAskForSecret, otr3.SMPEventAskForAnswer:
		e.securityChange = SMPSecretNeeded
		e.smpQuestion = question
		e.waitingForSecret = true
	case otr3.SMPEventSuccess:
		if progressPercent == 100 {
			e.securityChange = SMPComplete
		}
	case otr3.SMPEventAbort, otr3.SMPEventFailure, otr3.SMPEventCheated:
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
	c.SetSmpEventHandler(&c.eventHandler)
	c.SetErrorMessageHandler(&c.eventHandler)
	c.SetMessageEventHandler(&c.eventHandler)
	c.SetSecurityEventHandler(&c.eventHandler)

	// x/crypto/otr has a minimum size for fragmentation
	if c.FragmentSize >= minFragmentSize {
		c.SetFragmentSize(uint16(c.FragmentSize))
	}

	c.initialized = true
}

func (c *Conversation) updateValues() {
	if c.Conversation.GetTheirKey() != nil {
		c.TheirPublicKey.PublicKey = *c.Conversation.GetTheirKey()
	}

	c.Conversation.SetKeys(&c.PrivateKey.PrivateKey, &c.TheirPublicKey.PublicKey)

	if c.eventHandler.securityChange == NewKeys {
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
	out, ret, err = c.Conversation.Receive(in)
	encrypted = c.IsEncrypted()

	if ret != nil {
		toSend = otr3.Bytes(ret)
	}

	c.updateValues()
	change = c.eventHandler.consumeSecurityChange()
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

	ret, _ := c.Conversation.End()

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

	var ret []otr3.ValidMessage
	if c.eventHandler.waitingForSecret {
		c.eventHandler.waitingForSecret = false
		ret, err = c.ProvideAuthenticationSecret(mutualSecret)
	} else {
		ret, err = c.StartAuthenticate(question, mutualSecret)
	}

	c.updateValues()
	return otr3.Bytes(ret), err
}
