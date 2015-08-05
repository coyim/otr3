package otr3

import (
	"bytes"
	"crypto/sha256"
)

const minimumMessageLength = 3 // length of protocol version (SHORT) and message type (BYTE)

func (c *Conversation) generateNewDHKeyPair() error {
	x, err := c.randMPI(make([]byte, 40))
	if err != nil {
		return err
	}

	c.keys.generateNewDHKeyPair(x)
	wipeBigInt(x)

	return nil
}

func (c *Conversation) akeHasFinished() error {
	c.msgState = encrypted

	if c.OurKey.PublicKey == *c.TheirKey {
		messageEventReflected(c)
	}

	return c.generateNewDHKeyPair()
}

// Returns a AKE message (with header)
func (c *Conversation) receiveAKE(msgType byte, msg []byte) (toSend messageWithHeader, err error) {
	c.ensureAKE()

	switch msgType {
	case msgTypeDHCommit:
		c.ake.state, toSend, err = c.ake.state.receiveDHCommitMessage(c, msg)
	case msgTypeDHKey:
		c.ake.state, toSend, err = c.ake.state.receiveDHKeyMessage(c, msg)
	case msgTypeRevealSig:
		c.ake.state, toSend, err = c.ake.state.receiveRevealSigMessage(c, msg)
	case msgTypeSig:
		c.ake.state, toSend, err = c.ake.state.receiveSigMessage(c, msg)
	default:
		err = newOtrErrorf("unknown message type 0x%X", msgType)
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
	revealSigMsg messageWithHeader
}

type authState interface {
	receiveDHCommitMessage(*Conversation, []byte) (authState, messageWithHeader, error)
	receiveDHKeyMessage(*Conversation, []byte) (authState, messageWithHeader, error)
	receiveRevealSigMessage(*Conversation, []byte) (authState, messageWithHeader, error)
	receiveSigMessage(*Conversation, []byte) (authState, messageWithHeader, error)
}

func (authStateBase) receiveDHCommitMessage(c *Conversation, msg []byte) (authState, messageWithHeader, error) {
	return authStateNone{}.receiveDHCommitMessage(c, msg)
}

func (s authStateNone) receiveDHCommitMessage(c *Conversation, msg []byte) (authState, messageWithHeader, error) {
	dhKeyMsg, err := c.dhKeyMessage()
	if err != nil {
		return s, nil, err
	}
	dhKeyMsg, err = c.wrapMessageHeader(msgTypeDHKey, dhKeyMsg)
	if err != nil {
		return s, nil, err
	}

	if err = c.processDHCommit(msg); err != nil {
		return s, nil, err
	}

	return authStateAwaitingRevealSig{}, dhKeyMsg, nil
}

func (s authStateAwaitingRevealSig) receiveDHCommitMessage(c *Conversation, msg []byte) (authState, messageWithHeader, error) {
	//Forget the DH-commit received before we sent the DH-Key

	if err := c.processDHCommit(msg); err != nil {
		return s, nil, err
	}

	dhKeyMsg, err := c.wrapMessageHeader(msgTypeDHKey, c.serializeDHKey())
	if err != nil {
		return s, nil, err
	}

	return authStateAwaitingRevealSig{}, dhKeyMsg, nil
}

func (s authStateAwaitingDHKey) receiveDHCommitMessage(c *Conversation, msg []byte) (authState, messageWithHeader, error) {
	newMsg, _, ok1 := extractData(msg)
	_, theirHashedGx, ok2 := extractData(newMsg)

	if !ok1 || !ok2 {
		return s, nil, errInvalidOTRMessage
	}

	gxMPI := appendMPI(nil, c.ake.theirPublicValue)
	hashedGx := sha256.Sum256(gxMPI)
	if bytes.Compare(hashedGx[:], theirHashedGx) == 1 {
		dhCommitMsg, err := c.wrapMessageHeader(msgTypeDHCommit, c.serializeDHCommit(c.ake.theirPublicValue))
		if err != nil {
			return s, nil, err
		}
		return authStateAwaitingRevealSig{}, dhCommitMsg, nil
	}

	return authStateNone{}.receiveDHCommitMessage(c, msg)
}

func (s authStateNone) receiveDHKeyMessage(c *Conversation, msg []byte) (authState, messageWithHeader, error) {
	return s, nil, nil
}

func (s authStateAwaitingRevealSig) receiveDHKeyMessage(c *Conversation, msg []byte) (authState, messageWithHeader, error) {
	return s, nil, nil
}

func (s authStateAwaitingDHKey) receiveDHKeyMessage(c *Conversation, msg []byte) (authState, messageWithHeader, error) {
	_, err := c.processDHKey(msg)
	if err != nil {
		return s, nil, err
	}

	var revealSigMsg []byte
	if revealSigMsg, err = c.revealSigMessage(); err != nil {
		return s, nil, err
	}
	revealSigMsg, err = c.wrapMessageHeader(msgTypeRevealSig, revealSigMsg)
	if err != nil {
		return s, nil, err
	}

	c.keys.theirCurrentDHPubKey = setBigInt(c.keys.theirCurrentDHPubKey, c.ake.theirPublicValue)
	c.keys.ourCurrentDHKeys.pub = setBigInt(c.keys.ourCurrentDHKeys.pub, c.ake.ourPublicValue)
	c.keys.ourCurrentDHKeys.priv = setBigInt(c.keys.ourCurrentDHKeys.priv, c.ake.secretExponent)
	c.keys.ourCounter++

	return authStateAwaitingSig{revealSigMsg: revealSigMsg}, revealSigMsg, nil
}

func (s authStateAwaitingSig) receiveDHKeyMessage(c *Conversation, msg []byte) (authState, messageWithHeader, error) {
	isSame, err := c.processDHKey(msg)
	if err != nil {
		return s, nil, err
	}

	if isSame {
		// Retransmit the Reveal Signature Message
		return s, s.revealSigMsg, nil
	}

	return s, nil, nil
}

func (s authStateNone) receiveRevealSigMessage(c *Conversation, msg []byte) (authState, messageWithHeader, error) {
	return s, nil, nil
}

func (s authStateAwaitingRevealSig) receiveRevealSigMessage(c *Conversation, msg []byte) (authState, messageWithHeader, error) {
	err := c.processRevealSig(msg)

	if err != nil {
		return nil, nil, err
	}
	sigMsg, err := c.sigMessage()
	if err != nil {
		return s, nil, err
	}
	sigMsg, err = c.wrapMessageHeader(msgTypeSig, sigMsg)
	if err != nil {
		return s, nil, err
	}

	c.keys.theirCurrentDHPubKey = setBigInt(c.keys.theirCurrentDHPubKey, c.ake.theirPublicValue)
	wipeBigInt(c.keys.theirPreviousDHPubKey)

	c.keys.ourCurrentDHKeys.priv = setBigInt(c.keys.ourCurrentDHKeys.priv, c.ake.secretExponent)
	c.keys.ourCurrentDHKeys.pub = setBigInt(c.keys.ourCurrentDHKeys.pub, c.ake.ourPublicValue)
	c.keys.ourCounter++

	return authStateNone{}, sigMsg, c.akeHasFinished()
}

func (s authStateAwaitingDHKey) receiveRevealSigMessage(c *Conversation, msg []byte) (authState, messageWithHeader, error) {
	return s, nil, nil
}

func (s authStateAwaitingSig) receiveRevealSigMessage(c *Conversation, msg []byte) (authState, messageWithHeader, error) {
	return s, nil, nil
}

func (s authStateNone) receiveSigMessage(c *Conversation, msg []byte) (authState, messageWithHeader, error) {
	return s, nil, nil
}

func (s authStateAwaitingRevealSig) receiveSigMessage(c *Conversation, msg []byte) (authState, messageWithHeader, error) {
	return s, nil, nil
}

func (s authStateAwaitingDHKey) receiveSigMessage(c *Conversation, msg []byte) (authState, messageWithHeader, error) {
	return s, nil, nil
}

func (s authStateAwaitingSig) receiveSigMessage(c *Conversation, msg []byte) (authState, messageWithHeader, error) {
	err := c.processSig(msg)

	if err != nil {
		return nil, nil, err
	}

	//gy was stored when we receive DH-Key
	c.keys.theirCurrentDHPubKey = setBigInt(c.keys.theirCurrentDHPubKey, c.ake.theirPublicValue)
	wipeBigInt(c.keys.theirPreviousDHPubKey)

	return authStateNone{}, nil, c.akeHasFinished()
}

func (authStateNone) String() string              { return "AUTHSTATE_NONE" }
func (authStateAwaitingDHKey) String() string     { return "AUTHSTATE_AWAITING_DHKEY" }
func (authStateAwaitingRevealSig) String() string { return "AUTHSTATE_AWAITING_REVEALSIG" }
func (authStateAwaitingSig) String() string       { return "AUTHSTATE_AWAITING_SIG" }
