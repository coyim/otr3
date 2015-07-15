package otr3

import (
	"io"
	"testing"
)

var (
	fixtureY  = bnFromHex("abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd")
	fixtureGy = bnFromHex("2cdacabb00e63d8949aa85f7e6a095b1ee81a60779e58f8938ff1a7ed1e651d954bd739162e699cc73b820728af53aae60a46d529620792ddf839c5d03d2d4e92137a535b27500e3b3d34d59d0cd460d1f386b5eb46a7404b15c1ef84840697d2d3d2405dcdda351014d24a8717f7b9c51f6c84de365fea634737ae18ba22253a8e15249d9beb2dded640c6c0d74e4f7e19161cf828ce3ffa9d425fb68c0fddcaa7cbe81a7a5c2c595cce69a255059d9e5c04b49fb15901c087e225da850ff27")
)

func dhMsgType(msg []byte) byte {
	return msg[2]
}

func newAkeContext(v otrVersion, r io.Reader) akeContext {
	return akeContext{version: v, Rand: r}
}

func fixtureAKE() AKE {
	return AKE{
		akeContext: newAkeContext(otrV3{}, fixtureRand()),
	}
}

func fixtureDHCommitMsg() []byte {
	ake := fixtureAKE()
	msg, _ := ake.dhCommitMessage()
	return msg
}

func Test_receiveDHCommit_TransitionsFromNoneToAwaitingRevealSigAndSendDHCommitMsg(t *testing.T) {
	c := newAkeContext(otrV3{}, fixtureRand())
	msg := fixtureDHCommitMsg()
	state := authStateNone{}
	nextState, nextMsg, err := state.receiveDHCommitMessage(c, msg)

	assertEquals(t, err, nil)
	assertEquals(t, nextState, authStateAwaitingRevealSig{})
	assertEquals(t, dhMsgType(nextMsg), msgTypeDHKey)
}

func Test_receiveDHCommit_ResendPreviousDHCommitMsgFromAwaitingRevealSig(t *testing.T) {
	c := newAkeContext(otrV3{}, fixtureRand())
	//Should be done by ReceiveOTRQueryMsg
	c.gy = fixtureGy

	msg := fixtureDHCommitMsg()
	_, dhKeyMsg, err := authStateNone{}.receiveDHCommitMessage(c, msg)
	assertEquals(t, err, nil)

	nextState, nextMsg, err := authStateAwaitingRevealSig{}.receiveDHCommitMessage(c, msg)

	assertEquals(t, err, nil)
	assertEquals(t, nextState, authStateAwaitingRevealSig{})
	assertEquals(t, dhMsgType(nextMsg), msgTypeDHKey)
	assertDeepEquals(t, dhKeyMsg, nextMsg)
}

func Test_generateCommitMsgInstanceTags(t *testing.T) {
	senderInstanceTag := uint32(0x00000101)

	dhCommitAke := fixtureAKE()
	dhCommitAke.senderInstanceTag = senderInstanceTag
	dhCommitMsg, _ := dhCommitAke.dhCommitMessage()

	ake := fixtureAKE()
	generateCommitMsgInstanceTags(&ake, dhCommitMsg)

	assertEquals(t, ake.receiverInstanceTag, senderInstanceTag)
	assertEquals(t, ake.senderInstanceTag, generateIntanceTag())
}
