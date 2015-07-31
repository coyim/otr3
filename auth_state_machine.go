package otr3

import (
	"bytes"
	"crypto/sha256"
)

// ignoreMessage should never be called with a too small message buffer, it is assumed the caller will have checked this before calling it
func (c *Conversation) ignoreMessage(msg []byte) bool {
	_, protocolVersion, _ := extractShort(msg)
	unexpectedV2Msg := protocolVersion == 2 && !c.policies.has(allowV2)
	unexpectedV3Msg := protocolVersion == 3 && !c.policies.has(allowV3)

	return unexpectedV2Msg || unexpectedV3Msg
}

const minimumMessageLength = 3 // length of protocol version (SHORT) and message type (BYTE)

func (c *Conversation) generateNewDHKeyPair() error {
	x, ok := c.randMPI(make([]byte, 40))
	if !ok {
		return errShortRandomRead
	}

	c.keys.generateNewDHKeyPair(x)

	return nil
}

func (c *Conversation) resolveVersionFromDHCommitMessage(message []byte) otrVersion {
	_, msgProtocolVersion, _ := extractShort(message)
	return newOtrVersion(msgProtocolVersion)
}

func (c *Conversation) akeHasFinished() error {
	c.msgState = encrypted
	if err := c.generateNewDHKeyPair(); err != nil {
		return err
	}

	return nil
}

func (c *Conversation) receiveAKE(msg []byte) (toSend []byte, err error) {
	if len(msg) < minimumMessageLength {
		return nil, errInvalidOTRMessage
	}

	c.ensureAKE()

	if c.ignoreMessage(msg) {
		return
	}

	switch msg[2] {
	case msgTypeDHCommit:
		c.version = c.resolveVersionFromDHCommitMessage(msg)
		c.ake.state, toSend, err = c.ake.state.receiveDHCommitMessage(c, msg)
	case msgTypeDHKey:
		c.ake.state, toSend, err = c.ake.state.receiveDHKeyMessage(c, msg)

		//TODO: Verify.
		if !c.policies.has(allowV2) {
			//Accodring to the spec, Signature and Reveal Signature messages will be
			//ignored if V2 is not allowed, so the user will never finish the AKE
			//So I'm finishing the AKE
			err = c.akeHasFinished()
		}
	case msgTypeRevealSig:
		c.ake.state, toSend, err = c.ake.state.receiveRevealSigMessage(c, msg)
		if err == nil {
			err = c.akeHasFinished()
		}
	case msgTypeSig:
		c.ake.state, toSend, err = c.ake.state.receiveSigMessage(c, msg)
		if err == nil {
			err = c.akeHasFinished()
		}
	default:
		err = newOtrErrorf("unknown message type 0x%X", msg[2])
	}

	return
}

type authStateBase struct{}
type authStateNone struct{ authStateBase }
type authStateAwaitingDHKey struct{ authStateBase }
type authStateAwaitingRevealSig struct{ authStateBase }
type authStateAwaitingSig struct {
	authStateBase
	// revealSigMsg is only used to store the message so we can re-transmit it if needed
	revealSigMsg []byte
}
type authStateV1Setup struct{ authStateBase }

type authState interface {
	receiveDHCommitMessage(*Conversation, []byte) (authState, []byte, error)
	receiveDHKeyMessage(*Conversation, []byte) (authState, []byte, error)
	receiveRevealSigMessage(*Conversation, []byte) (authState, []byte, error)
	receiveSigMessage(*Conversation, []byte) (authState, []byte, error)
}

func (authStateBase) receiveDHCommitMessage(c *Conversation, msg []byte) (authState, []byte, error) {
	return authStateNone{}.receiveDHCommitMessage(c, msg)
}

func (s authStateNone) receiveDHCommitMessage(c *Conversation, msg []byte) (authState, []byte, error) {
	if _, err := c.parseMessageHeader(msg); err != nil {
		return s, nil, err
	}

	ret, err := c.dhKeyMessage()
	if err != nil {
		return s, nil, err
	}

	if err = c.processDHCommit(msg); err != nil {
		return s, nil, err
	}

	return authStateAwaitingRevealSig{}, ret, nil
}

func (s authStateAwaitingRevealSig) receiveDHCommitMessage(c *Conversation, msg []byte) (authState, []byte, error) {
	//Forget the DH-commit received before we sent the DH-Key

	if err := c.processDHCommit(msg); err != nil {
		return s, nil, err
	}

	//TODO: this should not change my instanceTag, since this is supposed to be a retransmit
	// We can ignore errors from this function, since processDHCommit checks for the same conditions
	c.parseMessageHeader(msg)

	return authStateAwaitingRevealSig{}, c.serializeDHKey(), nil
}

func (s authStateAwaitingDHKey) receiveDHCommitMessage(c *Conversation, msg []byte) (authState, []byte, error) {
	newMsg, err := c.parseMessageHeader(msg)
	if err != nil {
		return s, nil, err
	}

	newMsg, _, ok1 := extractData(newMsg)
	_, theirHashedGx, ok2 := extractData(newMsg)

	if !ok1 || !ok2 {
		return s, nil, errInvalidOTRMessage
	}

	gxMPI := appendMPI(nil, c.ake.theirPublicValue)
	hashedGx := sha256.Sum256(gxMPI)
	if bytes.Compare(hashedGx[:], theirHashedGx) == 1 {
		//NOTE what about the sender and receiver instance tags?
		return authStateAwaitingRevealSig{}, c.serializeDHCommit(c.ake.theirPublicValue), nil
	}

	return authStateNone{}.receiveDHCommitMessage(c, msg)
}

func (s authStateNone) receiveDHKeyMessage(c *Conversation, msg []byte) (authState, []byte, error) {
	return s, nil, nil
}

func (s authStateAwaitingRevealSig) receiveDHKeyMessage(c *Conversation, msg []byte) (authState, []byte, error) {
	return s, nil, nil
}

func (s authStateAwaitingDHKey) receiveDHKeyMessage(c *Conversation, msg []byte) (authState, []byte, error) {
	_, err := c.processDHKey(msg)
	if err != nil {
		return s, nil, err
	}

	var revealSigMsg []byte
	if revealSigMsg, err = c.revealSigMessage(); err != nil {
		return s, nil, err
	}

	c.keys.theirCurrentDHPubKey = c.ake.theirPublicValue
	c.keys.ourCurrentDHKeys.pub = c.ake.ourPublicValue
	c.keys.ourCurrentDHKeys.priv = c.ake.secretExponent
	c.keys.ourCounter++

	return authStateAwaitingSig{revealSigMsg: revealSigMsg}, revealSigMsg, nil
}

func (s authStateAwaitingSig) receiveDHKeyMessage(c *Conversation, msg []byte) (authState, []byte, error) {
	isSame, err := c.processDHKey(msg)
	if err != nil {
		return s, nil, err
	}

	if isSame {
		return s, s.revealSigMsg, nil
	}

	return s, nil, nil
}

func (s authStateNone) receiveRevealSigMessage(c *Conversation, msg []byte) (authState, []byte, error) {
	return s, nil, nil
}

func (s authStateAwaitingRevealSig) receiveRevealSigMessage(c *Conversation, msg []byte) (authState, []byte, error) {
	//TODO: Verify
	if !c.policies.has(allowV2) {
		//Accodring to the spec, Signature and Reveal Signature messages will be
		//ignored if V2 is not allowed, so the user will never finish the AKE
		//So I'm finishing the AKE
		err := c.akeHasFinished()
		return s, nil, err
	}

	err := c.processRevealSig(msg)

	if err != nil {
		return nil, nil, err
	}

	ret, err := c.sigMessage()
	if err != nil {
		return s, nil, err
	}

	c.keys.theirCurrentDHPubKey = c.ake.theirPublicValue
	c.keys.theirPreviousDHPubKey = nil

	c.keys.ourCurrentDHKeys.priv = c.ake.secretExponent
	c.keys.ourCurrentDHKeys.pub = c.ake.ourPublicValue
	c.keys.ourCounter++

	return authStateNone{}, ret, nil
}

func (s authStateAwaitingDHKey) receiveRevealSigMessage(c *Conversation, msg []byte) (authState, []byte, error) {
	return s, nil, nil
}

func (s authStateAwaitingSig) receiveRevealSigMessage(c *Conversation, msg []byte) (authState, []byte, error) {
	return s, nil, nil
}

func (s authStateNone) receiveSigMessage(c *Conversation, msg []byte) (authState, []byte, error) {
	return s, nil, nil
}

func (s authStateAwaitingRevealSig) receiveSigMessage(c *Conversation, msg []byte) (authState, []byte, error) {
	return s, nil, nil
}

func (s authStateAwaitingDHKey) receiveSigMessage(c *Conversation, msg []byte) (authState, []byte, error) {
	return s, nil, nil
}

func (s authStateAwaitingSig) receiveSigMessage(c *Conversation, msg []byte) (authState, []byte, error) {
	if !c.policies.has(allowV2) {
		return s, nil, nil
	}

	err := c.processSig(msg)

	if err != nil {
		return nil, nil, err
	}

	//gy was stored when we receive DH-Key
	c.keys.theirCurrentDHPubKey = c.ake.theirPublicValue
	c.keys.theirPreviousDHPubKey = nil

	return authStateNone{}, nil, nil
}

func (authStateNone) String() string              { return "AUTHSTATE_NONE" }
func (authStateAwaitingDHKey) String() string     { return "AUTHSTATE_AWAITING_DHKEY" }
func (authStateAwaitingRevealSig) String() string { return "AUTHSTATE_AWAITING_REVEALSIG" }
func (authStateAwaitingSig) String() string       { return "AUTHSTATE_AWAITING_SIG" }
func (authStateV1Setup) String() string           { return "AUTHSTATE_V1_SETUP" }

//TODO need to implements AUTHSTATE_V1_SETUP
