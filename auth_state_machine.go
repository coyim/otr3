package otr3

import (
	"bytes"
	"crypto/sha256"
	"fmt"
)

// ignoreMessage should never be called with a too small message buffer, it is assumed the caller will have checked this before calling it
func (c *conversation) ignoreMessage(msg []byte) bool {
	_, protocolVersion, _ := extractShort(msg)
	unexpectedV2Msg := protocolVersion == 2 && !c.policies.has(allowV2)
	unexpectedV3Msg := protocolVersion == 3 && !c.policies.has(allowV3)

	return unexpectedV2Msg || unexpectedV3Msg
}

const minimumMessageLength = 3 // length of protocol version (SHORT) and message type (BYTE)

func (c *conversation) generateNewDHKeyPair() error {
	x, ok := c.randMPI(make([]byte, 40))
	if !ok {
		return errShortRandomRead
	}

	c.keys.generateNewDHKeyPair(x)

	return nil
}

func (c *conversation) receiveAKE(msg []byte) (toSend []byte, err error) {
	if len(msg) < minimumMessageLength {
		return nil, errInvalidOTRMessage
	}

	c.ensureAKE()

	if c.ignoreMessage(msg) {
		return
	}

	switch msg[2] {
	case msgTypeDHCommit:
		c.ake.state, toSend, err = c.ake.state.receiveDHCommitMessage(c, msg)
	case msgTypeDHKey:
		c.ake.state, toSend, err = c.ake.state.receiveDHKeyMessage(c, msg)
	case msgTypeRevealSig:
		c.ake.state, toSend, err = c.ake.state.receiveRevealSigMessage(c, msg)
		if err == nil {
			c.msgState = encrypted
			c.keys.ourKeyID = 1
			if err = c.generateNewDHKeyPair(); err != nil {
				return
			}
		}
	case msgTypeSig:
		c.ake.state, toSend, err = c.ake.state.receiveSigMessage(c, msg)
		if err == nil {
			c.msgState = encrypted
			c.keys.ourKeyID = 1
			if err = c.generateNewDHKeyPair(); err != nil {
				return
			}
		}
	default:
		err = fmt.Errorf("otr: unknown message type 0x%X", msg[2])
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
	receiveDHCommitMessage(*conversation, []byte) (authState, []byte, error)
	receiveDHKeyMessage(*conversation, []byte) (authState, []byte, error)
	receiveRevealSigMessage(*conversation, []byte) (authState, []byte, error)
	receiveSigMessage(*conversation, []byte) (authState, []byte, error)
}

func (authStateBase) receiveDHCommitMessage(c *conversation, msg []byte) (authState, []byte, error) {
	return authStateNone{}.receiveDHCommitMessage(c, msg)
}

func (s authStateNone) receiveDHCommitMessage(c *conversation, msg []byte) (authState, []byte, error) {
	if err := generateCommitMsgInstanceTags(c, msg); err != nil {
		return s, nil, err
	}

	ret, err := c.dhKeyMessage()
	if err != nil {
		return s, nil, err
	}

	if err = c.processDHCommit(msg); err != nil {
		return s, nil, err
	}

	c.keys.ourKeyID = 1

	return authStateAwaitingRevealSig{}, ret, nil
}

func generateCommitMsgInstanceTags(ake *conversation, msg []byte) error {
	if ake.version.needInstanceTag() {
		if len(msg) < lenMsgHeader+4 {
			return errInvalidOTRMessage
		}

		_, receiverInstanceTag, _ := extractWord(msg[lenMsgHeader:])
		ake.ourInstanceTag = generateInstanceTag()
		ake.theirInstanceTag = receiverInstanceTag
	}
	return nil
}

func generateInstanceTag() uint32 {
	//TODO generate this
	return 0x00000100 + 0x01
}

func (s authStateAwaitingRevealSig) receiveDHCommitMessage(c *conversation, msg []byte) (authState, []byte, error) {
	//Forget the DH-commit received before we sent the DH-Key

	if err := c.processDHCommit(msg); err != nil {
		return s, nil, err
	}

	//TODO: this should not change my instanceTag, since this is supposed to be a retransmit
	// We can ignore errors from this function, since processDHCommit checks for the sameconditions
	generateCommitMsgInstanceTags(c, msg)

	return authStateAwaitingRevealSig{}, c.serializeDHKey(), nil
}

func (s authStateAwaitingDHKey) receiveDHCommitMessage(c *conversation, msg []byte) (authState, []byte, error) {
	if len(msg) < c.version.headerLen() {
		return s, nil, errInvalidOTRMessage
	}

	newMsg, _, ok1 := extractData(msg[c.version.headerLen():])
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

func (s authStateNone) receiveDHKeyMessage(c *conversation, msg []byte) (authState, []byte, error) {
	return s, nil, nil
}

func (s authStateAwaitingRevealSig) receiveDHKeyMessage(c *conversation, msg []byte) (authState, []byte, error) {
	return s, nil, nil
}

func (s authStateAwaitingDHKey) receiveDHKeyMessage(c *conversation, msg []byte) (authState, []byte, error) {
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

func (s authStateAwaitingSig) receiveDHKeyMessage(c *conversation, msg []byte) (authState, []byte, error) {
	isSame, err := c.processDHKey(msg)
	if err != nil {
		return s, nil, err
	}

	if isSame {
		return s, s.revealSigMsg, nil
	}

	return s, nil, nil
}

func (s authStateNone) receiveRevealSigMessage(c *conversation, msg []byte) (authState, []byte, error) {
	return s, nil, nil
}

func (s authStateAwaitingRevealSig) receiveRevealSigMessage(c *conversation, msg []byte) (authState, []byte, error) {
	if !c.policies.has(allowV2) {
		return s, nil, nil
	}

	err := c.processRevealSig(msg)

	if err != nil {
		return nil, nil, err
	}

	ret, err := c.sigMessage()
	if err != nil {
		return s, nil, err
	}

	//TODO: check if theirKeyID (or the previous) mathches what we have stored for this
	c.keys.ourKeyID = 0
	c.keys.theirCurrentDHPubKey = c.ake.theirPublicValue
	c.keys.theirPreviousDHPubKey = nil

	c.keys.ourCurrentDHKeys.priv = c.ake.secretExponent
	c.keys.ourCurrentDHKeys.pub = c.ake.ourPublicValue
	c.keys.ourCounter++

	return authStateNone{}, ret, nil
}

func (s authStateAwaitingDHKey) receiveRevealSigMessage(c *conversation, msg []byte) (authState, []byte, error) {
	return s, nil, nil
}

func (s authStateAwaitingSig) receiveRevealSigMessage(c *conversation, msg []byte) (authState, []byte, error) {
	return s, nil, nil
}

func (s authStateNone) receiveSigMessage(c *conversation, msg []byte) (authState, []byte, error) {
	return s, nil, nil
}

func (s authStateAwaitingRevealSig) receiveSigMessage(c *conversation, msg []byte) (authState, []byte, error) {
	return s, nil, nil
}

func (s authStateAwaitingDHKey) receiveSigMessage(c *conversation, msg []byte) (authState, []byte, error) {
	return s, nil, nil
}

func (s authStateAwaitingSig) receiveSigMessage(c *conversation, msg []byte) (authState, []byte, error) {
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
	c.keys.ourKeyID = 0

	return authStateNone{}, nil, nil
}

func (authStateNone) String() string              { return "AUTHSTATE_NONE" }
func (authStateAwaitingDHKey) String() string     { return "AUTHSTATE_AWAITING_DHKEY" }
func (authStateAwaitingRevealSig) String() string { return "AUTHSTATE_AWAITING_REVEALSIG" }
func (authStateAwaitingSig) String() string       { return "AUTHSTATE_AWAITING_SIG" }
func (authStateV1Setup) String() string           { return "AUTHSTATE_V1_SETUP" }

//TODO need to implements AUTHSTATE_V1_SETUP
