package otr3

import (
	"bytes"
	"fmt"
	"strconv"
)

// ignoreMessage should never be called with a too small message buffer, it is assumed the caller will have checked this before calling it
func (c *akeContext) ignoreMessage(msg []byte) bool {
	_, protocolVersion, _ := extractShort(msg)
	unexpectedV2Msg := protocolVersion == 2 && !c.has(allowV2)
	unexpectedV3Msg := protocolVersion == 3 && !c.has(allowV3)

	return unexpectedV2Msg || unexpectedV3Msg
}

const minimumMessageLength = 3 // length of protocol version (SHORT) and message type (BYTE)

func (c *akeContext) receiveMessage(msg []byte) (toSend []byte, err error) {
	if len(msg) < minimumMessageLength {
		return nil, errInvalidOTRMessage
	}

	if c.ignoreMessage(msg) {
		return
	}

	switch msg[2] {
	case msgTypeDHCommit:
		c.authState, toSend, err = c.authState.receiveDHCommitMessage(c, msg)
	case msgTypeDHKey:
		c.authState, toSend, err = c.authState.receiveDHKeyMessage(c, msg)
	case msgTypeRevealSig:
		c.authState, toSend, err = c.authState.receiveRevealSigMessage(c, msg)
		if err == nil {
			c.msgState = encrypted
		}
	case msgTypeSig:
		c.authState, toSend, err = c.authState.receiveSigMessage(c, msg)
		if err == nil {
			c.msgState = encrypted
		}
	default:
		err = fmt.Errorf("otr: unknown message type 0x%X", msg[2])
	}

	return
}

func (c *akeContext) receiveQueryMessage(msg []byte) (toSend []byte, err error) {
	c.authState, toSend, err = c.authState.receiveQueryMessage(c, msg)
	return
}

type authStateNone struct{}
type authStateAwaitingDHKey struct{}
type authStateAwaitingRevealSig struct{}
type authStateAwaitingSig struct{}
type authStateV1Setup struct{}

type authState interface {
	receiveQueryMessage(*akeContext, []byte) (authState, []byte, error)
	receiveDHCommitMessage(*akeContext, []byte) (authState, []byte, error)
	receiveDHKeyMessage(*akeContext, []byte) (authState, []byte, error)
	receiveRevealSigMessage(*akeContext, []byte) (authState, []byte, error)
	receiveSigMessage(*akeContext, []byte) (authState, []byte, error)
}

func (s authStateNone) receiveQueryMessage(c *akeContext, msg []byte) (authState, []byte, error) {
	v, ok := s.acceptOTRRequest(c.policies, msg)
	if !ok {
		return nil, nil, errInvalidVersion
	}

	//TODO set the version for every existing otrContext
	c.otrVersion = v

	ake := c.newAKE()
	ake.senderInstanceTag = generateInstanceTag()

	out, err := ake.dhCommitMessage()
	if err != nil {
		return s, nil, err
	}

	c.r = ake.r
	c.x = ake.x
	c.gx = ake.gx

	return authStateAwaitingDHKey{}, out, nil
}

func (authStateNone) parseOTRQueryMessage(msg []byte) []int {
	ret := []int{}

	if bytes.HasPrefix(msg, queryMarker) && len(msg) > len(queryMarker) {
		versions := msg[len(queryMarker):]

		if versions[0] == '?' {
			ret = append(ret, 1)
			versions = versions[1:]
		}

		if len(versions) > 0 && versions[0] == 'v' {
			for _, c := range versions {
				if v, err := strconv.Atoi(string(c)); err == nil {
					ret = append(ret, v)
				}
			}
		}
	}

	return ret
}

func (s authStateNone) acceptOTRRequest(p policies, msg []byte) (otrVersion, bool) {
	versions := s.parseOTRQueryMessage(msg)

	for _, v := range versions {
		switch {
		case v == 3 && p.has(allowV3):
			return otrV3{}, true
		case v == 2 && p.has(allowV2):
			return otrV2{}, true
		}
	}

	return nil, false
}

func (authStateAwaitingDHKey) receiveQueryMessage(c *akeContext, msg []byte) (authState, []byte, error) {
	return authStateNone{}.receiveQueryMessage(c, msg)
}

func (authStateAwaitingRevealSig) receiveQueryMessage(c *akeContext, msg []byte) (authState, []byte, error) {
	return authStateNone{}.receiveQueryMessage(c, msg)
}

func (authStateAwaitingSig) receiveQueryMessage(c *akeContext, msg []byte) (authState, []byte, error) {
	return authStateNone{}.receiveQueryMessage(c, msg)
}

func (s authStateNone) receiveDHCommitMessage(c *akeContext, msg []byte) (authState, []byte, error) {
	ake := c.newAKE()

	if err := generateCommitMsgInstanceTags(&ake, msg); err != nil {
		return s, nil, err
	}

	ret, err := ake.dhKeyMessage()
	if err != nil {
		return s, nil, err
	}

	//TODO should we reset ourKeyID? Why?
	c.y = ake.y
	c.gy = ake.gy

	if err = ake.processDHCommit(msg); err != nil {
		return s, nil, err
	}

	c.encryptedGx = ake.encryptedGx
	c.hashedGx = ake.hashedGx

	return authStateAwaitingRevealSig{}, ret, nil
}

func generateCommitMsgInstanceTags(ake *AKE, msg []byte) error {
	if ake.needInstanceTag() {
		if len(msg) < lenMsgHeader+4 {
			return errInvalidOTRMessage
		}

		_, receiverInstanceTag, _ := extractWord(msg[lenMsgHeader:])
		ake.senderInstanceTag = generateInstanceTag()
		ake.receiverInstanceTag = receiverInstanceTag
	}
	return nil
}

func generateInstanceTag() uint32 {
	//TODO generate this
	return 0x00000100 + 0x01
}

func (s authStateAwaitingRevealSig) receiveDHCommitMessage(c *akeContext, msg []byte) (authState, []byte, error) {
	//Forget the DH-commit received before we sent the DH-Key

	ake := c.newAKE()

	if err := ake.processDHCommit(msg); err != nil {
		return s, nil, err
	}

	c.encryptedGx = ake.encryptedGx
	c.hashedGx = ake.hashedGx

	//TODO: this should not change my instanceTag, since this is supposed to be a retransmit
	// We can ignore errors from this function, since processDHCommit checks for the sameconditions
	generateCommitMsgInstanceTags(&ake, msg)

	return authStateAwaitingRevealSig{}, ake.serializeDHKey(), nil
}

func (s authStateAwaitingDHKey) receiveDHCommitMessage(c *akeContext, msg []byte) (authState, []byte, error) {
	if len(msg) < c.headerLen() {
		return s, nil, errInvalidOTRMessage
	}

	newMsg, _, ok1 := extractData(msg[c.headerLen():])
	_, theirHashedGx, ok2 := extractData(newMsg)

	if !ok1 || !ok2 {
		return s, nil, errInvalidOTRMessage
	}

	gxMPI := appendMPI(nil, c.gx)
	hashedGx := sha256Sum(gxMPI)
	if bytes.Compare(hashedGx[:], theirHashedGx) == 1 {
		ake := c.newAKE()
		//NOTE what about the sender and receiver instance tags?
		return authStateAwaitingRevealSig{}, ake.serializeDHCommit(), nil
	}

	return authStateNone{}.receiveDHCommitMessage(c, msg)
}

func (authStateAwaitingSig) receiveDHCommitMessage(c *akeContext, msg []byte) (authState, []byte, error) {
	return authStateNone{}.receiveDHCommitMessage(c, msg)
}

func (s authStateNone) receiveDHKeyMessage(c *akeContext, msg []byte) (authState, []byte, error) {
	return s, nil, nil
}

func (s authStateAwaitingRevealSig) receiveDHKeyMessage(c *akeContext, msg []byte) (authState, []byte, error) {
	return s, nil, nil
}

func (s authStateAwaitingDHKey) receiveDHKeyMessage(c *akeContext, msg []byte) (authState, []byte, error) {
	ake := c.newAKE()

	_, err := ake.processDHKey(msg)
	if err != nil {
		return s, nil, err
	}

	if c.revealSigMsg, err = ake.revealSigMessage(); err != nil {
		return s, nil, err
	}

	c.gy = ake.gy
	c.sigKey = ake.sigKey

	return authStateAwaitingSig{}, c.revealSigMsg, nil
}

func (s authStateAwaitingSig) receiveDHKeyMessage(c *akeContext, msg []byte) (authState, []byte, error) {
	ake := c.newAKE()
	isSame, err := ake.processDHKey(msg)
	if err != nil {
		return s, nil, err
	}

	if isSame {
		return s, c.revealSigMsg, nil
	}

	return s, nil, nil
}

func (s authStateNone) receiveRevealSigMessage(c *akeContext, msg []byte) (authState, []byte, error) {
	return s, nil, nil
}

func (s authStateAwaitingRevealSig) receiveRevealSigMessage(c *akeContext, msg []byte) (authState, []byte, error) {
	if !c.has(allowV2) {
		return s, nil, nil
	}

	ake := c.newAKE()
	err := ake.processRevealSig(msg)

	if err != nil {
		return nil, nil, err
	}

	//TODO: check if theirKeyID (or the previous) mathches what we have stored for this
	c.theirKeyID = ake.theirKeyID
	c.theirCurrentDHPubKey = ake.gx
	c.theirPreviousDHPubKey = nil

	ret, err := ake.sigMessage()

	return authStateNone{}, ret, err
}

func (s authStateAwaitingDHKey) receiveRevealSigMessage(c *akeContext, msg []byte) (authState, []byte, error) {
	return s, nil, nil
}

func (s authStateAwaitingSig) receiveRevealSigMessage(c *akeContext, msg []byte) (authState, []byte, error) {
	return s, nil, nil
}

func (s authStateNone) receiveSigMessage(c *akeContext, msg []byte) (authState, []byte, error) {
	return s, nil, nil
}

func (s authStateAwaitingRevealSig) receiveSigMessage(c *akeContext, msg []byte) (authState, []byte, error) {
	return s, nil, nil
}

func (s authStateAwaitingDHKey) receiveSigMessage(c *akeContext, msg []byte) (authState, []byte, error) {
	return s, nil, nil
}

func (s authStateAwaitingSig) receiveSigMessage(c *akeContext, msg []byte) (authState, []byte, error) {
	if !c.has(allowV2) {
		return s, nil, nil
	}

	ake := c.newAKE()
	err := ake.processSig(msg)

	if err != nil {
		return nil, nil, err
	}

	//TODO: check if theirKeyID (or the previous) mathches what we have stored for this
	c.theirKeyID = ake.theirKeyID
	//gy was stored when we receive DH-Key
	c.theirCurrentDHPubKey = c.gy
	c.theirPreviousDHPubKey = nil

	return authStateNone{}, nil, nil
}

func (authStateNone) String() string              { return "AUTHSTATE_NONE" }
func (authStateAwaitingDHKey) String() string     { return "AUTHSTATE_AWAITING_DHKEY" }
func (authStateAwaitingRevealSig) String() string { return "AUTHSTATE_AWAITING_REVEALSIG" }
func (authStateAwaitingSig) String() string       { return "AUTHSTATE_AWAITING_SIG" }
func (authStateV1Setup) String() string           { return "AUTHSTATE_V1_SETUP" }

//TODO need to implements AUTHSTATE_V1_SETUP
