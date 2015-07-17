package otr3

import (
	"bytes"
	"strconv"
)

func (c *akeContext) ignoreMessage(msg []byte) bool {
	protocolVersion := extractShort(msg, 0)
	unexpectedV2Msg := protocolVersion == 2 && !c.has(allowV2)
	unexpectedV3Msg := protocolVersion == 3 && !c.has(allowV3)

	return unexpectedV2Msg || unexpectedV3Msg
}

func (c *akeContext) receiveMessage(msg []byte) (toSend []byte) {
	msgType := msg[2]

	switch msgType {
	case msgTypeDHCommit:
		if c.ignoreMessage(msg) {
			//TODO error?
			return
		}

		c.authState, toSend = c.authState.receiveDHCommitMessage(c, msg)
	case msgTypeDHKey:
		if c.ignoreMessage(msg) {
			//TODO error?
			return
		}

		c.authState, toSend = c.authState.receiveDHKeyMessage(c, msg)
	case msgTypeRevealSig:
		if !c.has(allowV2) {
			//TODO error?
			return
		}

		//TODO error
		c.authState, toSend = c.authState.receiveRevealSigMessage(c, msg)

		//TODO set msgState = encrypted
	case msgTypeSig:
		if !c.has(allowV2) {
			//TODO error?
			return
		}

		//TODO error
		c.authState, toSend = c.authState.receiveSigMessage(c, msg)
	}

	return
}

func (c *akeContext) receiveQueryMessage(msg []byte) (toSend []byte) {
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
	receiveRevealSigMessage(*akeContext, []byte) (authState, []byte)
	receiveSigMessage(*akeContext, []byte) (authState, []byte)
}

func (s authStateNone) receiveQueryMessage(c *akeContext, msg []byte) (authState, []byte) {
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
	out, _ := ake.dhCommitMessage()

	c.x = ake.x
	c.gx = ake.gx

	return authStateAwaitingDHKey{}, out
}

func (authStateNone) parseOTRQueryMessage(msg []byte) []int {
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
	ake := c.newAKE()

	generateCommitMsgInstanceTags(&ake, msg)

	//TODO error
	msg, _ = ake.dhKeyMessage()

	//TODO should we reset ourKeyID? Why?
	c.y = ake.y
	c.gy = ake.gy

	return authStateAwaitingRevealSig{}, msg
}

func generateCommitMsgInstanceTags(ake *AKE, msg []byte) {
	if ake.needInstanceTag() {
		//TODO error
		receiverInstanceTag, _ := extractWord(msg[lenMsgHeader:], 0)
		ake.senderInstanceTag = generateIntanceTag()
		ake.receiverInstanceTag = receiverInstanceTag
	}
}

func generateIntanceTag() uint32 {
	//TODO generate this
	return 0x00000100 + 0x01
}

func (authStateAwaitingRevealSig) receiveDHCommitMessage(c *akeContext, msg []byte) (authState, []byte) {
	//TODO: error when gy = nil when we define the error strategy
	//TODO: error when y = nil when we define the error strategy

	index, encryptedGx := extractData(msg, 11)
	c.encryptedGx = encryptedGx
	_, h := extractData(msg, index)
	copy(c.hashedGx[:], h)

	ake := c.newAKE()

	//TODO: this should not change my instanceTag, since this is supposed to be a retransmit
	generateCommitMsgInstanceTags(&ake, msg)

	//TODO error
	msg, _ = ake.serializeDHKey()
	return authStateAwaitingRevealSig{}, msg
}

func (authStateAwaitingDHKey) receiveDHCommitMessage(c *akeContext, msg []byte) (authState, []byte) {
	ake := c.newAKE()

	//TODO error
	index, _ := extractData(msg, 11)
	_, theirHashedGx := extractData(msg, index)

	hashedGx := sha256Sum(ake.gx.Bytes())
	if bytes.Compare(hashedGx[:], theirHashedGx) == 1 {
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
	_, c.gy = extractMPI(msg, 11)

	ake := AKE{
		akeContext: *c,
	}
	msg, _ = ake.revealSigMessage()
	//TODO handle error

	return authStateAwaitingSig{}, msg
}

func (authStateAwaitingSig) receiveDHKeyMessage(c *akeContext, msg []byte) (authState, []byte) {
	return nil, nil
}

func (s authStateNone) receiveRevealSigMessage(c *akeContext, msg []byte) (authState, []byte) {
	return s, nil
}

func (s authStateAwaitingRevealSig) receiveRevealSigMessage(c *akeContext, msg []byte) (authState, []byte) {
	ake := c.newAKE()
	err := ake.processRevealSig(msg)

	if err != nil {
		//TODO errors
		return nil, nil
	}

	//TODO errors
	ret, err := ake.sigMessage()

	return authStateNone{}, ret
}

func (s authStateAwaitingDHKey) receiveRevealSigMessage(c *akeContext, msg []byte) (authState, []byte) {
	return s, nil
}

func (s authStateAwaitingSig) receiveRevealSigMessage(c *akeContext, msg []byte) (authState, []byte) {
	return s, nil
}

func (s authStateNone) receiveSigMessage(c *akeContext, msg []byte) (authState, []byte) {
	return nil, nil
}

func (s authStateAwaitingRevealSig) receiveSigMessage(c *akeContext, msg []byte) (authState, []byte) {
	return nil, nil
}

func (s authStateAwaitingDHKey) receiveSigMessage(c *akeContext, msg []byte) (authState, []byte) {
	return nil, nil
}

func (s authStateAwaitingSig) receiveSigMessage(c *akeContext, msg []byte) (authState, []byte) {
	//do something
	return nil, nil
}

func (authStateNone) String() string              { return "AUTHSTATE_NONE" }
func (authStateAwaitingDHKey) String() string     { return "AUTHSTATE_AWAITING_DHKEY" }
func (authStateAwaitingRevealSig) String() string { return "AUTHSTATE_AWAITING_REVEALSIG" }
func (authStateAwaitingSig) String() string       { return "AUTHSTATE_AWAITING_SIG" }
func (authStateV1Setup) String() string           { return "AUTHSTATE_V1_SETUP" }

//TODO need to implements AUTHSTATE_V1_SETUP
