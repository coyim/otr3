package otr3

import (
	"bytes"
)

func (c *akeContext) receiveMessage(msg []byte) (toSend []byte) {
	msgType := msg[2]

	switch msgType {
	case msgTypeDHCommit:
		c.authState, toSend = c.authState.receiveDHCommitMessage(c, msg)
	case msgTypeDHKey:
		//c.authState, toSend, _ = c.receiveDHKey(message)
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
	//receiveDHKeyMessage(*akeContext, []byte) (authState, []byte)
	//receiveRevealSigMessage(*akeContext, []byte) (authState, []byte)
	//receiveSigMessage(*akeContext, []byte) (authState, []byte)
}

func (s authStateNone) receiveQueryMessage(c *akeContext, msg []byte) (authState, []byte) {
	v := s.acceptOTRRequest(msg)
	if v == nil {
		//TODO errors
	}

	//TODO set the version for every existing otrContext
	c.otrVersion = v

	ake := &AKE{
		akeContext: *c,
	}

	ake.senderInstanceTag = generateIntanceTag()

	//TODO errors
	out, _ := ake.dhCommitMessage()

	c.x = ake.x
	c.gx = ake.gx

	return authStateAwaitingDHKey{}, out
}

func (authStateNone) acceptOTRRequest(msg []byte) otrVersion {
	//TODO implement policy
	version := 0
	versions := parseOTRQueryMessage(msg)

	for _, v := range versions {
		if v > version {
			version = v
		}
	}

	switch version {
	case 2:
		return otrV2{}
	case 3:
		return otrV3{}
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
	ake := &AKE{
		akeContext: *c,
	}

	generateCommitMsgInstanceTags(ake, msg)

	//TODO error
	msg, _ = ake.dhKeyMessage()

	//TODO should we reset myKeyID? Why?
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
	_, c.hashedGx = extractData(msg, index)

	ake := &AKE{
		akeContext: *c,
	}

	//TODO: this should not change my instanceTag, since this is supposed to be a retransmit
	generateCommitMsgInstanceTags(ake, msg)

	//TODO error
	msg, _ = ake.serializeDHKey()
	return authStateAwaitingRevealSig{}, msg
}

func (authStateAwaitingDHKey) receiveDHCommitMessage(c *akeContext, msg []byte) (authState, []byte) {
	ake := AKE{
		akeContext: *c,
	}

	//TODO error
	index, _ := extractData(msg, 11)
	_, theirHashedGx := extractData(msg, index)

	if bytes.Compare(sha256Sum(ake.gx.Bytes()), theirHashedGx) == 1 {
		//NOTE what about the sender and receiver instance tags?
		return authStateAwaitingRevealSig{}, ake.serializeDHCommit()
	}

	return authStateNone{}.receiveDHCommitMessage(c, msg)
}

func (authStateAwaitingSig) receiveDHCommitMessage(c *akeContext, msg []byte) (authState, []byte) {
	return authStateNone{}.receiveDHCommitMessage(c, msg)
}

//TODO need to implements AUTHSTATE_V1_SETUP