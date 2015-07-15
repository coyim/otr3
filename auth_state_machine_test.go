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
	return akeContext{
		otrContext: otrContext{
			otrVersion: v,
			Rand:       r,
		},
	}
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

func Test_receiveDHCommit_TransitionsFromNoneToAwaitingRevealSigAndSendDHKeyMsg(t *testing.T) {
	c := newAkeContext(otrV3{}, fixtureRand())
	nextState, nextMsg, err := authStateNone{}.receiveDHCommitMessage(&c, fixtureDHCommitMsg())

	assertEquals(t, err, nil)
	assertEquals(t, nextState, authStateAwaitingRevealSig{})
	assertEquals(t, dhMsgType(nextMsg), msgTypeDHKey)
}

func Test_receiveDHCommit_AtAuthStateNoneStoresGyAndY(t *testing.T) {
	c := newAkeContext(otrV3{}, fixtureRand())
	_, _, err := authStateNone{}.receiveDHCommitMessage(&c, fixtureDHCommitMsg())

	assertEquals(t, err, nil)
	assertDeepEquals(t, c.gy, fixtureGy)
	assertDeepEquals(t, c.y, fixtureY)
}

func Test_receiveDHCommit_ResendPreviousDHKeyMsgFromAwaitingRevealSig(t *testing.T) {
	c := newAkeContext(otrV3{}, fixtureRand())

	authAwaitingRevSig, prevDHKeyMsg, err := authStateNone{}.receiveDHCommitMessage(&c, fixtureDHCommitMsg())
	assertEquals(t, err, nil)
	assertEquals(t, authAwaitingRevSig, authStateAwaitingRevealSig{})

	nextState, msg, err := authAwaitingRevSig.receiveDHCommitMessage(&c, fixtureDHCommitMsg())

	assertEquals(t, err, nil)
	assertEquals(t, nextState, authStateAwaitingRevealSig{})
	assertEquals(t, dhMsgType(msg), msgTypeDHKey)
	assertDeepEquals(t, prevDHKeyMsg, msg)
}

func Test_receiveDHCommit_AtAuthAwaitingRevealSigiForgetOldEncryptedGxAndHashedGx(t *testing.T) {
	c := newAkeContext(otrV3{}, fixtureRand())
	//TODO needs to stores encryptedGx and hashedGx when it is generated
	c.encryptedGx = []byte{0x02} //some encryptedGx
	c.hashedGx = []byte{0x05}    //some hashedGx

	newDHCommitMsg := fixtureDHCommitMsg()
	hashedGxIndex, newEncryptedGx := extractData(newDHCommitMsg, 11)
	_, newHashedGx := extractData(newDHCommitMsg, hashedGxIndex)

	authStateNone{}.receiveDHCommitMessage(&c, fixtureDHCommitMsg())

	_, _, err := authStateAwaitingRevealSig{}.receiveDHCommitMessage(&c, newDHCommitMsg)
	assertEquals(t, err, nil)
	assertDeepEquals(t, c.encryptedGx, newEncryptedGx)
	assertDeepEquals(t, c.hashedGx, newHashedGx)
}

func Test_receiveDHCommit_AtAuthAwaitingSigTransitionsToAwaitingRevSigAndSendsNewDHKeyMsg(t *testing.T) {
	c := newAkeContext(otrV3{}, fixtureRand())

	authAwaitingRevSig, msg, err := authStateAwaitingSig{}.receiveDHCommitMessage(&c, fixtureDHCommitMsg())
	assertEquals(t, err, nil)
	assertEquals(t, authAwaitingRevSig, authStateAwaitingRevealSig{})
	assertEquals(t, dhMsgType(msg), msgTypeDHKey)
}

func Test_generateDHCommitMsgInstanceTags(t *testing.T) {
	senderInstanceTag := uint32(0x00000101)

	dhCommitAke := fixtureAKE()
	dhCommitAke.senderInstanceTag = senderInstanceTag
	dhCommitMsg, _ := dhCommitAke.dhCommitMessage()

	ake := fixtureAKE()
	generateCommitMsgInstanceTags(&ake, dhCommitMsg)

	assertEquals(t, ake.receiverInstanceTag, senderInstanceTag)
	assertEquals(t, ake.senderInstanceTag, generateIntanceTag())
}
