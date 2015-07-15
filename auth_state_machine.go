package otr3

type authStateNone struct{}
type authStateAwaitingDHKey struct{}
type authStateAwaitingRevealSig struct{}
type authStateAwaitingSig struct{}
type authStateV1Setup struct{}

type authState interface {
	//receiveQueryMessage(*akeContext, []byte) (authState, []byte, error)
	receiveDHCommitMessage(*akeContext, []byte) (authState, []byte, error)
	//receiveDHKeyMessage(context, []byte) (authState, []byte, error)
	//receiveRevealSigMessage(context, []byte) (authState, []byte, error)
	//receiveSigMessage(context, []byte) (authState, []byte, error)
}

func (authStateNone) receiveDHCommitMessage(c *akeContext, msg []byte) (authState, []byte, error) {
	ake := &AKE{
		akeContext: *c,
	}

	generateCommitMsgInstanceTags(ake, msg)

	msg, err := ake.dhKeyMessage()

	c.y = ake.y
	c.gy = ake.gy

	return authStateAwaitingRevealSig{}, msg, err
}

func generateCommitMsgInstanceTags(ake *AKE, msg []byte) {
	if ake.needInstanceTag() {
		receiverInstanceTag, _ := extractWord(msg[lenMsgHeader:], 0)
		ake.senderInstanceTag = generateIntanceTag()
		ake.receiverInstanceTag = receiverInstanceTag
	}

}

func generateIntanceTag() uint32 {
	//TODO generate this
	return 0x00000100 + 0x01
}

func (authStateAwaitingRevealSig) receiveDHCommitMessage(c *akeContext, msg []byte) (authState, []byte, error) {
	//TODO: error when gy = nil when we define the error strategy
	//TODO: error when y = nil when we define the error strategy

	ake := &AKE{
		akeContext: *c,
	}

	//TODO: this should not change my instanceTag, since this is supposed to be a retransmit
	generateCommitMsgInstanceTags(ake, msg)

	msg, err := ake.serializeDHKey()
	return authStateAwaitingRevealSig{}, msg, err
}

func (authStateAwaitingDHKey) receiveDHCommitMessage(c *akeContext, msg []byte) (authState, []byte, error) {
	//This is the trickest transition in the whole protocol
	return nil, nil, nil
}

func (authStateAwaitingSig) receiveDHCommitMessage(c *akeContext, msg []byte) (authState, []byte, error) {
	return authStateNone{}.receiveDHCommitMessage(c, msg)
}
