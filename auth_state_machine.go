package otr3

import (
	"bytes"
	"errors"
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
		return nil, errors.New("otr: invalid OTR message")
	}

	if c.ignoreMessage(msg) {
		return
	}

	switch msg[2] {
	case msgTypeDHCommit:
		c.authState, toSend = c.authState.receiveDHCommitMessage(c, msg)
	case msgTypeDHKey:
		c.authState, toSend = c.authState.receiveDHKeyMessage(c, msg)
	case msgTypeRevealSig:
		c.authState, toSend, _ = c.authState.receiveRevealSigMessage(c, msg)
		c.msgState = encrypted
	case msgTypeSig:
		c.authState, toSend, _ = c.authState.receiveSigMessage(c, msg)
		c.msgState = encrypted
	default:
		err = fmt.Errorf("otr: unknown message type 0x%X", msg[2])
	}

	return
}

func (c *akeContext) receiveQueryMessage(msg []byte) (toSend []byte) {
	// TODO: errors?
	c.authState, toSend = c.authState.receiveQueryMessage(c, msg)
	return
}

type authStateNone struct{}
type authStateAwaitingDHKey struct{}
type authStateAwaitingRevealSig struct{}
type authStateAwaitingSig struct{}
type authStateV1Setup struct{}

type authState interface {
	receiveQueryMessage(*akeContext, []byte) (authState, []byte)
	receiveDHCommitMessage(*akeContext, []byte) (authState, []byte)
	receiveDHKeyMessage(*akeContext, []byte) (authState, []byte)
	receiveRevealSigMessage(*akeContext, []byte) (authState, []byte, error)
	receiveSigMessage(*akeContext, []byte) (authState, []byte, error)
}

func (s authStateNone) receiveQueryMessage(c *akeContext, msg []byte) (authState, []byte) {
	// TODO: errors?
	v := s.acceptOTRRequest(c.policies, msg)
	if v == nil {
		//TODO errors
		//version could not be accepted by the given policy
		return nil, nil
	}

	//TODO set the version for every existing otrContext
	c.otrVersion = v

	ake := c.newAKE()
	ake.senderInstanceTag = generateIntanceTag()

	//TODO errors
	out, _ := ake.generateDHCommitMessage()

	c.r = ake.r
	c.x = ake.x
	c.gx = ake.gx

	return authStateAwaitingDHKey{}, out
}

func (authStateNone) parseOTRQueryMessage(msg []byte) []int {
	// TODO: errors?
	ret := []int{}

	if bytes.HasPrefix(msg, queryMarker) {
		var p int
		versions := msg[len(queryMarker):]

		if versions[p] == '?' {
			ret = append(ret, 1)
			p++
		}

		if len(versions) > p && versions[p] == 'v' {
			for _, c := range versions[p:] {
				if v, err := strconv.Atoi(string(c)); err == nil {
					ret = append(ret, v)
				}
			}
		}
	}

	return ret
}

func (s authStateNone) acceptOTRRequest(p policies, msg []byte) otrVersion {
	// TODO: errors?
	versions := s.parseOTRQueryMessage(msg)

	for _, v := range versions {
		switch {
		case v == 3 && p.has(allowV3):
			return otrV3{}
		case v == 2 && p.has(allowV2):
			return otrV2{}
		}
	}

	return nil
}

func (authStateAwaitingDHKey) receiveQueryMessage(c *akeContext, msg []byte) (authState, []byte) {
	return authStateNone{}.receiveQueryMessage(c, msg)
}

func (authStateAwaitingRevealSig) receiveQueryMessage(c *akeContext, msg []byte) (authState, []byte) {
	return authStateNone{}.receiveQueryMessage(c, msg)
}

func (authStateAwaitingSig) receiveQueryMessage(c *akeContext, msg []byte) (authState, []byte) {
	return authStateNone{}.receiveQueryMessage(c, msg)
}

func (authStateNone) receiveDHCommitMessage(c *akeContext, msg []byte) (authState, []byte) {
	// TODO: errors?
	ake := c.newAKE()

	generateCommitMsgInstanceTags(&ake, msg)

	//TODO error
	ret, _ := ake.generateDHKeyMessage()

	//TODO should we reset ourKeyID? Why?
	c.y = ake.y
	c.gy = ake.gy
	ake.processDHCommit(msg)
	c.encryptedGx = ake.encryptedGx
	c.hashedGx = ake.hashedGx

	return authStateAwaitingRevealSig{}, ret
}

func generateCommitMsgInstanceTags(ake *AKE, msg []byte) {
	// TODO: errors?
	if ake.needInstanceTag() {
		//TODO error
		_, receiverInstanceTag, _ := extractWord(msg[lenMsgHeader:])
		ake.senderInstanceTag = generateIntanceTag()
		ake.receiverInstanceTag = receiverInstanceTag
	}
}

func generateIntanceTag() uint32 {
	//TODO generate this
	return 0x00000100 + 0x01
}

func (s authStateAwaitingRevealSig) receiveDHCommitMessage(c *akeContext, msg []byte) (authState, []byte) {
	// TODO: errors?
	//Forget the DH-commit received before we sent the DH-Key

	//TODO: error if gy OR y = nil when we define the error strategy
	//They should have been stored when we sent the previous DH-Key

	ake := c.newAKE()

	ake.processDHCommit(msg)
	c.encryptedGx = ake.encryptedGx
	c.hashedGx = ake.hashedGx

	//TODO: this should not change my instanceTag, since this is supposed to be a retransmit
	generateCommitMsgInstanceTags(&ake, msg)

	return authStateAwaitingRevealSig{}, ake.serializeDHKey()
}

func (authStateAwaitingDHKey) receiveDHCommitMessage(c *akeContext, msg []byte) (authState, []byte) {
	//TODO error
	newMsg, _, _ := extractData(msg[c.headerLen():])
	_, theirHashedGx, _ := extractData(newMsg)

	gxMPI := appendMPI(nil, c.gx)
	hashedGx := sha256Sum(gxMPI)
	if bytes.Compare(hashedGx[:], theirHashedGx) == 1 {
		ake := c.newAKE()
		//NOTE what about the sender and receiver instance tags?
		return authStateAwaitingRevealSig{}, ake.serializeDHCommit()
	}

	return authStateNone{}.receiveDHCommitMessage(c, msg)
}

func (authStateAwaitingSig) receiveDHCommitMessage(c *akeContext, msg []byte) (authState, []byte) {
	return authStateNone{}.receiveDHCommitMessage(c, msg)
}

func (s authStateNone) receiveDHKeyMessage(c *akeContext, msg []byte) (authState, []byte) {
	return s, nil
}

func (s authStateAwaitingRevealSig) receiveDHKeyMessage(c *akeContext, msg []byte) (authState, []byte) {
	return s, nil
}

func (authStateAwaitingDHKey) receiveDHKeyMessage(c *akeContext, msg []byte) (authState, []byte) {
	// TODO: errors?
	ake := c.newAKE()
	ake.processDHKey(msg)

	c.revealSigMsg, _ = ake.generateRevealSigMessage()

	c.gy = ake.gy
	c.sigKey = ake.sigKey

	return authStateAwaitingSig{}, c.revealSigMsg
}

func (s authStateAwaitingSig) receiveDHKeyMessage(c *akeContext, msg []byte) (authState, []byte) {
	// TODO: errors?
	ake := c.newAKE()
	isSame, _ := ake.processDHKey(msg)
	//TODO handle errors

	if isSame {
		return s, c.revealSigMsg
	}

	return s, nil
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

	ret, err := ake.generateSigMessage()

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

	return authStateNone{}, nil, nil
}

func (authStateNone) String() string              { return "AUTHSTATE_NONE" }
func (authStateAwaitingDHKey) String() string     { return "AUTHSTATE_AWAITING_DHKEY" }
func (authStateAwaitingRevealSig) String() string { return "AUTHSTATE_AWAITING_REVEALSIG" }
func (authStateAwaitingSig) String() string       { return "AUTHSTATE_AWAITING_SIG" }
func (authStateV1Setup) String() string           { return "AUTHSTATE_V1_SETUP" }

//TODO need to implements AUTHSTATE_V1_SETUP
