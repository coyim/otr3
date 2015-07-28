package otr3

import (
	"crypto/sha256"
	"errors"
	"math/big"
	"testing"
)

func dhMsgType(msg []byte) byte {
	return msg[2]
}

func fixtureConversation() *conversation {
	return fixtureConversationWithVersion(otrV3{})
}

func fixtureConversationV2() *conversation {
	return fixtureConversationWithVersion(otrV2{})
}

func fixtureConversationWithVersion(v otrVersion) *conversation {
	return newConversation(v, fixtureRand())
}

func fixtureDHCommitMsg() []byte {
	ake := fixtureConversation()
	ake.ourInstanceTag = generateInstanceTag()
	msg, _ := ake.dhCommitMessage()
	return msg
}

func fixtureDHKeyMsg(v otrVersion) []byte {
	ake := fixtureConversationWithVersion(v)
	ake.ourKey = alicePrivateKey
	msg, _ := ake.dhKeyMessage()
	return msg
}

func fixtureRevealSigMsg(v otrVersion) []byte {
	ake := bobContextAtReceiveDHKey()
	ake.version = v

	msg, _ := ake.revealSigMessage()

	return msg
}

func fixtureSigMsg(v otrVersion) []byte {
	ake := aliceContextAtReceiveRevealSig()
	ake.version = v

	msg, _ := ake.sigMessage()

	return msg
}

func bobContextAfterAKE() *conversation {
	c := newConversation(otrV3{}, fixtureRand())
	c.keys.ourKeyID = 1
	c.keys.ourCurrentDHKeys.pub = fixedgx
	c.keys.ourPreviousDHKeys.priv = fixedx
	c.keys.ourPreviousDHKeys.pub = fixedgx

	c.keys.theirKeyID = 1
	c.keys.theirCurrentDHPubKey = fixedgy

	return c
}

func bobContextAtAwaitingSig() *conversation {
	c := bobContextAtReceiveDHKey()
	c.version = otrV2{}
	c.policies.add(allowV2)
	c.ake.state = authStateAwaitingSig{}

	return c
}

func bobContextAtReceiveDHKey() *conversation {
	c := bobContextAtAwaitingDHKey()
	c.ake.theirPublicValue = fixedgy // stored at receiveDHKey

	copy(c.ake.sigKey.c[:], bytesFromHex("d942cc80b66503414c05e3752d9ba5c4"))
	copy(c.ake.sigKey.m1[:], bytesFromHex("b6254b8eab0ad98152949454d23c8c9b08e4e9cf423b27edc09b1975a76eb59c"))
	copy(c.ake.sigKey.m2[:], bytesFromHex("954be27015eeb0455250144d906e83e7d329c49581aea634c4189a3c981184f5"))

	return c
}

func bobContextAtAwaitingDHKey() *conversation {
	c := newConversation(otrV3{}, fixtureRand())
	c.startAKE()
	c.policies.add(allowV3)
	c.ake.state = authStateAwaitingDHKey{}
	c.ourKey = bobPrivateKey

	copy(c.ake.r[:], fixedr)    // stored at sendDHCommit
	c.setSecretExponent(fixedx) // stored at sendDHCommit

	return c
}

func aliceContextAtReceiveRevealSig() *conversation {
	c := aliceContextAtAwaitingRevealSig()
	c.ake.theirPublicValue = fixedgx // Alice decrypts encryptedGx using r

	return c
}

func aliceContextAtAwaitingRevealSig() *conversation {
	c := newConversation(otrV2{}, fixtureRand())
	c.startAKE()
	c.policies.add(allowV2)
	c.ake.state = authStateAwaitingRevealSig{}
	c.ourKey = alicePrivateKey

	copy(c.ake.hashedGx[:], expectedHashedGxValue) //stored at receiveDHCommit
	c.ake.encryptedGx = expectedEncryptedGxValue   //stored at receiveDHCommit

	c.setSecretExponent(fixedy) //stored at sendDHKey

	return c
}

func Test_receiveQueryMessage_SendDHCommitAndTransitToStateAwaitingDHKey(t *testing.T) {
	queryMsg := []byte("?OTRv3?")

	c := newConversation(nil, fixtureRand())
	c.policies.add(allowV3)
	msg, _ := c.receiveQueryMessage(queryMsg)

	assertEquals(t, c.ake.state, authStateAwaitingDHKey{})
	assertDeepEquals(t, fixtureDHCommitMsg(), msg)
}

func Test_receiveQueryMessage_StoresRAndXAndGx(t *testing.T) {
	fixture := fixtureConversation()
	fixture.dhCommitMessage()

	msg := []byte("?OTRv3?")
	cxt := newConversation(nil, fixtureRand())
	cxt.policies.add(allowV3)

	cxt.receiveQueryMessage(msg)
	assertDeepEquals(t, cxt.ake.r, fixture.ake.r)
	assertDeepEquals(t, cxt.ake.secretExponent, fixture.ake.secretExponent)
	assertDeepEquals(t, cxt.ake.ourPublicValue, fixture.ake.ourPublicValue)
}

func Test_parseOTRQueryMessage(t *testing.T) {
	var exp = map[string][]int{
		"?OTR?":     []int{1},
		"?OTRv2?":   []int{2},
		"?OTRv23?":  []int{2, 3},
		"?OTR?v2":   []int{1, 2},
		"?OTRv248?": []int{2, 4, 8},
		"?OTR?v?":   []int{1},
		"?OTRv?":    []int{},
	}

	for queryMsg, versions := range exp {
		m := []byte(queryMsg)
		assertDeepEquals(t, parseOTRQueryMessage(m), versions)
	}
}

func Test_acceptOTRRequest_returnsNilForUnsupportedVersions(t *testing.T) {
	p := policies(0)
	msg := []byte("?OTR?")
	v, ok := acceptOTRRequest(p, msg)

	assertEquals(t, v, nil)
	assertEquals(t, ok, false)
}

func Test_acceptOTRRequest_acceptsOTRV3IfHasAllowV3Policy(t *testing.T) {
	msg := []byte("?OTRv32?")
	p := policies(0)
	p.allowV2()
	p.allowV3()
	v, ok := acceptOTRRequest(p, msg)

	assertEquals(t, v, otrV3{})
	assertEquals(t, ok, true)
}

func Test_acceptOTRRequest_acceptsOTRV2IfHasOnlyAllowV2Policy(t *testing.T) {
	msg := []byte("?OTRv32?")
	p := policies(0)
	p.allowV2()
	v, ok := acceptOTRRequest(p, msg)

	assertEquals(t, v, otrV2{})
	assertEquals(t, ok, true)
}

func Test_receiveDHCommit_TransitionsFromNoneToAwaitingRevealSigAndSendDHKeyMsg(t *testing.T) {
	c := newConversation(otrV3{}, fixtureRand())
	nextState, nextMsg, e := authStateNone{}.receiveDHCommitMessage(c, fixtureDHCommitMsg())

	assertEquals(t, nextState, authStateAwaitingRevealSig{})
	assertEquals(t, dhMsgType(nextMsg), msgTypeDHKey)
	assertEquals(t, e, nil)
}

func Test_receiveDHCommit_AtAuthStateNoneStoresGyAndY(t *testing.T) {
	c := newConversation(otrV3{}, fixtureRand())
	authStateNone{}.receiveDHCommitMessage(c, fixtureDHCommitMsg())

	assertDeepEquals(t, c.ake.ourPublicValue, fixedgy)
	assertDeepEquals(t, c.ake.secretExponent, fixedy)
}

func Test_receiveDHCommit_AtAuthStateNoneStoresEncryptedGxAndHashedGx(t *testing.T) {
	c := newConversation(otrV3{}, fixtureRand())

	dhCommitMsg := fixtureDHCommitMsg()
	newMsg, encryptedGx, _ := extractData(dhCommitMsg[c.version.headerLen():])
	_, hashedGx, _ := extractData(newMsg)

	authStateNone{}.receiveDHCommitMessage(c, dhCommitMsg)

	assertDeepEquals(t, c.ake.hashedGx[:], hashedGx)
	assertDeepEquals(t, c.ake.encryptedGx, encryptedGx)
}

func Test_receiveDHCommit_ResendPreviousDHKeyMsgFromAwaitingRevealSig(t *testing.T) {
	c := newConversation(otrV3{}, fixtureRand())

	authAwaitingRevSig, prevDHKeyMsg, _ := authStateNone{}.receiveDHCommitMessage(c, fixtureDHCommitMsg())
	assertEquals(t, authAwaitingRevSig, authStateAwaitingRevealSig{})

	nextState, msg, _ := authAwaitingRevSig.receiveDHCommitMessage(c, fixtureDHCommitMsg())

	assertEquals(t, nextState, authStateAwaitingRevealSig{})
	assertEquals(t, dhMsgType(msg), msgTypeDHKey)
	assertDeepEquals(t, prevDHKeyMsg, msg)
}

func Test_receiveDHCommit_AtAuthAwaitingRevealSigiForgetOldEncryptedGxAndHashedGx(t *testing.T) {
	c := newConversation(otrV3{}, fixtureRand())
	c.startAKE()
	//TODO needs to stores encryptedGx and hashedGx when it is generated
	c.ake.encryptedGx = []byte{0x02}         //some encryptedGx
	c.ake.hashedGx = [sha256.Size]byte{0x05} //some hashedGx

	newDHCommitMsg := fixtureDHCommitMsg()
	newMsg, newEncryptedGx, _ := extractData(newDHCommitMsg[c.version.headerLen():])
	_, newHashedGx, _ := extractData(newMsg)

	authStateNone{}.receiveDHCommitMessage(c, fixtureDHCommitMsg())

	authStateAwaitingRevealSig{}.receiveDHCommitMessage(c, newDHCommitMsg)
	assertDeepEquals(t, c.ake.encryptedGx, newEncryptedGx)
	assertDeepEquals(t, c.ake.hashedGx[:], newHashedGx)
}

func Test_receiveDHCommit_AtAuthAwaitingSigTransitionsToAwaitingRevSigAndSendsNewDHKeyMsg(t *testing.T) {
	c := newConversation(otrV3{}, fixtureRand())

	authAwaitingRevSig, msg, _ := authStateAwaitingSig{}.receiveDHCommitMessage(c, fixtureDHCommitMsg())
	assertEquals(t, authAwaitingRevSig, authStateAwaitingRevealSig{})
	assertEquals(t, dhMsgType(msg), msgTypeDHKey)
}

func Test_receiveDHCommit_AtAwaitingDHKeyIgnoreIncomingMsgAndResendOurDHCommitMsgIfOurHashIsHigher(t *testing.T) {
	ourDHCommitAKE := fixtureConversation()
	ourDHMsg, _ := ourDHCommitAKE.dhCommitMessage()

	//make sure we store the same alues when creating the DH commit
	c := newConversation(otrV3{}, fixtureRand())
	c.startAKE()
	c.ake.encryptedGx = ourDHCommitAKE.ake.encryptedGx
	c.ake.theirPublicValue = ourDHCommitAKE.ake.ourPublicValue

	// force their hashedGx to be lower than ours
	msg := fixtureDHCommitMsg()
	newPoint, _, _ := extractData(msg[c.version.headerLen():])
	newPoint[4] = 0x00

	state, newMsg, _ := authStateAwaitingDHKey{}.receiveDHCommitMessage(c, msg)
	assertEquals(t, state, authStateAwaitingRevealSig{})
	assertDeepEquals(t, newMsg, ourDHMsg)
}

func Test_receiveDHCommit_AtAwaitingDHKeyForgetOurGxAndSendDHKeyMsgAndGoToAwaitingRevealSig(t *testing.T) {
	ourDHCommitAKE := fixtureConversation()
	ourDHCommitAKE.dhCommitMessage()

	//make sure we store the same values when creating the DH commit
	c := newConversation(otrV3{}, fixtureRand())
	c.startAKE()
	c.ake.theirPublicValue = ourDHCommitAKE.ake.ourPublicValue

	// force their hashedGx to be higher than ours
	msg := fixtureDHCommitMsg()
	newPoint, _, _ := extractData(msg[c.version.headerLen():])
	newPoint[4] = 0xFF

	state, newMsg, _ := authStateAwaitingDHKey{}.receiveDHCommitMessage(c, msg)
	assertEquals(t, state, authStateAwaitingRevealSig{})
	assertEquals(t, dhMsgType(newMsg), msgTypeDHKey)
	assertDeepEquals(t, c.ake.ourPublicValue, fixedgy)
	assertDeepEquals(t, c.ake.secretExponent, fixedy)
}

func Test_receiveDHKey_AtAuthStateNoneOrAuthStateAwaitingRevealSigIgnoreIt(t *testing.T) {
	var nilB []byte
	c := newConversation(otrV3{}, fixtureRand())
	c.startAKE()
	dhKeymsg := fixtureDHKeyMsg(otrV3{})

	states := []authState{
		authStateNone{},
		authStateAwaitingRevealSig{},
	}

	for _, s := range states {
		state, msg, err := s.receiveDHKeyMessage(c, dhKeymsg)
		assertEquals(t, err, nil)
		assertEquals(t, state, s)
		assertDeepEquals(t, msg, nilB)
	}
}

func Test_receiveDHKey_TransitionsFromAwaitingDHKeyToAwaitingSigAndSendsRevealSig(t *testing.T) {
	ourDHCommitAKE := fixtureConversation()
	ourDHCommitAKE.dhCommitMessage()

	c := bobContextAtAwaitingDHKey()

	state, msg, _ := authStateAwaitingDHKey{}.receiveDHKeyMessage(c, fixtureDHKeyMsg(otrV3{}))

	//TODO before generate rev si need to extract their gy from DH commit
	_, ok := state.(authStateAwaitingSig)
	assertEquals(t, ok, true)
	assertEquals(t, dhMsgType(msg), msgTypeRevealSig)
}

func Test_receiveDHKey_AtAwaitingDHKeyStoresGyAndSigKey(t *testing.T) {
	ourDHCommitAKE := fixtureConversation()
	ourDHCommitAKE.dhCommitMessage()

	c := bobContextAtAwaitingDHKey()

	_, _, err := authStateAwaitingDHKey{}.receiveDHKeyMessage(c, fixtureDHKeyMsg(otrV3{}))

	assertEquals(t, err, nil)
	assertDeepEquals(t, c.ake.theirPublicValue, fixedgy)
	assertDeepEquals(t, c.ake.sigKey.c[:], expectedC)
	assertDeepEquals(t, c.ake.sigKey.m1[:], expectedM1)
	assertDeepEquals(t, c.ake.sigKey.m2[:], expectedM2)
}

func Test_receiveDHKey_AtAwaitingDHKeyStoresOursAndTheirDHKeysAndIncreaseCounter(t *testing.T) {
	ourDHCommitAKE := fixtureConversation()
	ourDHCommitAKE.dhCommitMessage()

	c := bobContextAtAwaitingDHKey()

	_, _, err := authStateAwaitingDHKey{}.receiveDHKeyMessage(c, fixtureDHKeyMsg(otrV3{}))

	assertEquals(t, err, nil)
	assertDeepEquals(t, c.keys.theirCurrentDHPubKey, fixedgy)
	assertDeepEquals(t, c.keys.ourCurrentDHKeys.pub, fixedgx)
	assertDeepEquals(t, c.keys.ourCurrentDHKeys.priv, fixedx)
	assertEquals(t, c.keys.ourCounter, uint64(1))
	assertEquals(t, c.keys.ourKeyID, uint32(1))
	assertEquals(t, c.keys.theirKeyID, uint32(0))
}

func Test_receiveDHKey_AtAuthAwaitingSigIfReceivesSameDHKeyMsgRetransmitRevealSigMsg(t *testing.T) {
	ourDHCommitAKE := fixtureConversation()
	ourDHCommitAKE.dhCommitMessage()

	c := newConversation(otrV3{}, fixtureRand())
	c.startAKE()
	c.setSecretExponent(ourDHCommitAKE.ake.secretExponent)
	c.ourKey = bobPrivateKey

	sameDHKeyMsg := fixtureDHKeyMsg(otrV3{})
	sigState, previousRevealSig, _ := authStateAwaitingDHKey{}.receiveDHKeyMessage(c, sameDHKeyMsg)

	state, msg, _ := sigState.receiveDHKeyMessage(c, sameDHKeyMsg)

	//FIXME: What about gy and sigKey?
	_, sameStateType := state.(authStateAwaitingSig)
	assertDeepEquals(t, sameStateType, true)
	assertDeepEquals(t, msg, previousRevealSig)
}

func Test_receiveDHKey_AtAuthAwaitingSigIgnoresMsgIfIsNotSameDHKeyMsg(t *testing.T) {
	var nilB []byte

	newDHKeyMsg := fixtureDHKeyMsg(otrV3{})
	c := newConversation(otrV3{}, fixtureRand())
	c.startAKE()

	state, msg, _ := authStateAwaitingSig{}.receiveDHKeyMessage(c, newDHKeyMsg)

	_, sameStateType := state.(authStateAwaitingSig)
	assertDeepEquals(t, sameStateType, true)
	assertDeepEquals(t, msg, nilB)
}

func Test_receiveRevealSig_TransitionsFromAwaitingRevealSigToNoneOnSuccess(t *testing.T) {
	revealSignMsg := fixtureRevealSigMsg(otrV2{})

	c := aliceContextAtAwaitingRevealSig()

	state, msg, err := authStateAwaitingRevealSig{}.receiveRevealSigMessage(c, revealSignMsg)

	assertEquals(t, err, nil)
	assertEquals(t, state, authStateNone{})
	assertEquals(t, dhMsgType(msg), msgTypeSig)
}

func Test_receiveRevealSig_AtAwaitingRevealSigStoresOursAndTheirDHKeysAndIncreaseCounter(t *testing.T) {
	var nilBigInt *big.Int
	revealSignMsg := fixtureRevealSigMsg(otrV2{})

	c := aliceContextAtAwaitingRevealSig()

	_, _, err := authStateAwaitingRevealSig{}.receiveRevealSigMessage(c, revealSignMsg)

	assertEquals(t, err, nil)
	assertDeepEquals(t, c.keys.theirCurrentDHPubKey, fixedgx)
	assertDeepEquals(t, c.keys.theirPreviousDHPubKey, nilBigInt)
	assertDeepEquals(t, c.keys.ourCurrentDHKeys.pub, fixedgy)
	assertDeepEquals(t, c.keys.ourCurrentDHKeys.priv, fixedy)
	assertEquals(t, c.keys.ourCounter, uint64(1))
	assertEquals(t, c.keys.ourKeyID, uint32(1))
	assertEquals(t, c.keys.theirKeyID, uint32(1))
}

func Test_receiveRevealSig_IgnoreMessageIfNotInStateAwaitingRevealSig(t *testing.T) {
	var nilB []byte

	states := []authState{
		authStateNone{},
		authStateAwaitingDHKey{},
		authStateAwaitingSig{},
	}

	revealSignMsg := fixtureRevealSigMsg(otrV2{})

	for _, s := range states {
		c := newConversation(otrV3{}, fixtureRand())
		state, msg, err := s.receiveRevealSigMessage(c, revealSignMsg)

		assertEquals(t, err, nil)
		assertDeepEquals(t, state, s)
		assertDeepEquals(t, msg, nilB)
	}
}

func Test_receiveSig_TransitionsFromAwaitingSigToNoneOnSuccess(t *testing.T) {
	var nilB []byte
	sigMsg := fixtureSigMsg(otrV2{})
	c := bobContextAtAwaitingSig()

	state, msg, err := authStateAwaitingSig{}.receiveSigMessage(c, sigMsg)

	assertEquals(t, err, nil)
	assertEquals(t, state, authStateNone{})
	assertDeepEquals(t, msg, nilB)
	assertEquals(t, c.keys.theirKeyID, uint32(1))
}

func Test_receiveSig_IgnoreMessageIfNotInStateAwaitingSig(t *testing.T) {
	var nilB []byte

	states := []authState{
		authStateNone{},
		authStateAwaitingDHKey{},
		authStateAwaitingRevealSig{},
	}

	revealSignMsg := fixtureRevealSigMsg(otrV2{})

	for _, s := range states {
		c := newConversation(otrV3{}, fixtureRand())
		state, msg, err := s.receiveSigMessage(c, revealSignMsg)

		assertEquals(t, err, nil)
		assertEquals(t, state, s)
		assertDeepEquals(t, msg, nilB)
	}
}

func Test_generateDHCommitMsgInstanceTags(t *testing.T) {
	senderInstanceTag := uint32(0x00000101)

	dhCommitAke := fixtureConversation()
	dhCommitAke.ourInstanceTag = senderInstanceTag
	dhCommitMsg, _ := dhCommitAke.dhCommitMessage()

	ake := fixtureConversation()
	generateCommitMsgInstanceTags(ake, dhCommitMsg)

	assertEquals(t, ake.theirInstanceTag, senderInstanceTag)
	assertEquals(t, ake.ourInstanceTag, generateInstanceTag())
}

func Test_receiveMessage_ignoresDHCommitIfItsVersionIsNotInThePolicy(t *testing.T) {
	var nilB []byte
	cV2 := newConversation(otrV2{}, fixtureRand())
	cV2.policies.add(allowV2)

	cV3 := newConversation(otrV3{}, fixtureRand())
	cV3.policies.add(allowV3)

	ake := fixtureConversationV2()
	msgV2, _ := ake.dhCommitMessage()
	msgV3 := fixtureDHCommitMsg()

	toSend, _ := cV2.receiveAKE(msgV3)
	assertEquals(t, cV2.ake.state, authStateNone{})
	assertDeepEquals(t, toSend, nilB)

	toSend, _ = cV3.receiveAKE(msgV2)
	assertEquals(t, cV3.ake.state, authStateNone{})
	assertDeepEquals(t, toSend, nilB)
}

func Test_receiveMessage_ignoresDHKeyIfItsVersionIsNotInThePolicy(t *testing.T) {
	var nilB []byte
	cV2 := newConversation(otrV2{}, fixtureRand())
	cV2.ensureAKE()
	cV2.ake.state = authStateAwaitingDHKey{}
	cV2.policies.add(allowV2)

	cV3 := newConversation(otrV3{}, fixtureRand())
	cV3.ensureAKE()
	cV3.ake.state = authStateAwaitingDHKey{}
	cV3.policies.add(allowV3)

	msgV2 := fixtureDHKeyMsg(otrV2{})
	msgV3 := fixtureDHKeyMsg(otrV3{})

	toSend, _ := cV2.receiveAKE(msgV3)
	assertEquals(t, cV2.ake.state, authStateAwaitingDHKey{})
	assertDeepEquals(t, toSend, nilB)

	toSend, _ = cV3.receiveAKE(msgV2)
	assertEquals(t, cV3.ake.state, authStateAwaitingDHKey{})
	assertDeepEquals(t, toSend, nilB)
}

func Test_receiveMessage_ignoresRevealSigIfItsVersionIsNotInThePolicy(t *testing.T) {
	var nilB []byte
	cV2 := newConversation(otrV2{}, fixtureRand())
	cV2.ensureAKE()
	cV2.ake.state = authStateAwaitingRevealSig{}
	cV2.policies.add(allowV2)

	cV3 := newConversation(otrV3{}, fixtureRand())
	cV3.ensureAKE()
	cV3.ake.state = authStateAwaitingRevealSig{}
	cV3.policies.add(allowV3)

	msgV2 := fixtureRevealSigMsg(otrV2{})
	msgV3 := fixtureRevealSigMsg(otrV3{})

	toSend, _ := cV2.receiveAKE(msgV3)
	assertEquals(t, cV2.ake.state, authStateAwaitingRevealSig{})
	assertDeepEquals(t, toSend, nilB)

	toSend, _ = cV3.receiveAKE(msgV2)
	assertEquals(t, cV3.ake.state, authStateAwaitingRevealSig{})
	assertDeepEquals(t, toSend, nilB)
}

func Test_receiveMessage_ignoresSignatureIfItsVersionIsNotInThePolicy(t *testing.T) {
	var nilB []byte
	cV2 := newConversation(otrV2{}, fixtureRand())
	cV2.ensureAKE()
	cV2.ake.state = authStateAwaitingSig{}
	cV2.policies.add(allowV2)

	cV3 := newConversation(otrV3{}, fixtureRand())
	cV3.ensureAKE()
	cV3.ake.state = authStateAwaitingSig{}
	cV3.policies.add(allowV3)

	msgV2 := fixtureSigMsg(otrV2{})
	msgV3 := fixtureSigMsg(otrV3{})

	toSend, _ := cV2.receiveAKE(msgV3)
	_, sameStateType := cV2.ake.state.(authStateAwaitingSig)
	assertDeepEquals(t, sameStateType, true)
	assertDeepEquals(t, toSend, nilB)

	toSend, _ = cV3.receiveAKE(msgV2)
	_, sameStateType = cV3.ake.state.(authStateAwaitingSig)
	assertDeepEquals(t, sameStateType, true)
	assertDeepEquals(t, toSend, nilB)
}

func Test_receiveMessage_ignoresRevealSignaureIfDoesNotAllowV2(t *testing.T) {
	var nilB []byte
	cV2 := newConversation(otrV2{}, fixtureRand())
	cV2.ensureAKE()
	cV2.ake.state = authStateAwaitingRevealSig{}
	cV2.policies = policies(allowV3)

	cV3 := newConversation(otrV3{}, fixtureRand())
	cV3.ensureAKE()
	cV3.ake.state = authStateAwaitingRevealSig{}
	cV3.policies = policies(allowV3)

	msgV2 := fixtureRevealSigMsg(otrV2{})
	msgV3 := fixtureRevealSigMsg(otrV3{})

	toSend, _ := cV3.receiveAKE(msgV3)
	assertEquals(t, cV3.ake.state, authStateAwaitingRevealSig{})
	assertDeepEquals(t, toSend, nilB)

	toSend, _ = cV2.receiveAKE(msgV2)
	assertEquals(t, cV2.ake.state, authStateAwaitingRevealSig{})
	assertDeepEquals(t, toSend, nilB)
}

func Test_receiveMessage_ignoresSignatureIfDoesNotAllowV2(t *testing.T) {
	var nilB []byte
	cV2 := newConversation(otrV2{}, fixtureRand())
	cV2.ensureAKE()
	cV2.ake.state = authStateAwaitingSig{}
	cV2.policies = policies(allowV3)

	cV3 := newConversation(otrV3{}, fixtureRand())
	cV3.ensureAKE()
	cV3.ake.state = authStateAwaitingSig{}
	cV3.policies = policies(allowV3)

	msgV2 := fixtureSigMsg(otrV2{})
	msgV3 := fixtureSigMsg(otrV3{})

	toSend, _ := cV3.receiveAKE(msgV3)

	assertDeepEquals(t, cV3.ake.state, authStateAwaitingSig{})
	assertDeepEquals(t, toSend, nilB)
	toSend, _ = cV2.receiveAKE(msgV2)
	assertDeepEquals(t, cV2.ake.state, authStateAwaitingSig{})
	assertDeepEquals(t, toSend, nilB)
}

func Test_receiveMessage_returnsErrorIfTheMessageIsCorrupt(t *testing.T) {
	cV3 := newConversation(otrV3{}, fixtureRand())
	cV3.ensureAKE()
	cV3.ake.state = authStateAwaitingSig{}
	cV3.policies.add(allowV3)

	_, err := cV3.receiveAKE([]byte{})
	assertEquals(t, err, errInvalidOTRMessage)

	_, err = cV3.receiveAKE([]byte{0x00, 0x00})
	assertEquals(t, err, errInvalidOTRMessage)

	_, err = cV3.receiveAKE([]byte{0x00, 0x03, 0x56})
	assertDeepEquals(t, err, errors.New("otr: unknown message type 0x56"))
}

func Test_authStateAwaitingSig_receiveSigMessage_returnsErrorIfProcessSigFails(t *testing.T) {
	c := newConversation(otrV2{}, fixtureRand())
	c.policies.add(allowV2)
	_, _, err := authStateAwaitingSig{}.receiveSigMessage(c, []byte{0x00, 0x00})
	assertEquals(t, err, errInvalidOTRMessage)
}

func Test_authStateAwaitingRevealSig_receiveRevealSigMessage_returnsErrorIfProcessRevealSigFails(t *testing.T) {
	c := newConversation(otrV2{}, fixtureRand())
	c.policies.add(allowV2)
	_, _, err := authStateAwaitingRevealSig{}.receiveRevealSigMessage(c, []byte{0x00, 0x00})
	assertEquals(t, err, errInvalidOTRMessage)
}

func Test_receiveMessage_receiveRevealSigMessageAndSetMessageStateToEncrypted(t *testing.T) {
	c := aliceContextAtAwaitingRevealSig()
	msg := fixtureRevealSigMsg(otrV2{})
	assertEquals(t, c.msgState, plainText)

	_, err := c.receiveAKE(msg)

	assertEquals(t, err, nil)
	assertEquals(t, c.msgState, encrypted)
}

func Test_receiveMessage_receiveRevealSigMessageAndStoresTheirKeyIDAndTheirCurrentDHPubKey(t *testing.T) {
	var nilBigInt *big.Int

	c := aliceContextAtAwaitingRevealSig()
	msg := fixtureRevealSigMsg(otrV2{})
	assertEquals(t, c.msgState, plainText)

	_, err := c.receiveAKE(msg)

	assertEquals(t, err, nil)
	assertEquals(t, c.keys.theirKeyID, uint32(1))
	assertDeepEquals(t, c.keys.theirCurrentDHPubKey, fixedgx)
	assertEquals(t, c.keys.theirPreviousDHPubKey, nilBigInt)
}

func Test_receiveMessage_receiveSigMessageAndSetMessageStateToEncrypted(t *testing.T) {
	c := bobContextAtAwaitingSig()
	msg := fixtureSigMsg(otrV2{})
	assertEquals(t, c.msgState, plainText)

	_, err := c.receiveAKE(msg)

	assertEquals(t, err, nil)
	assertEquals(t, c.msgState, encrypted)
}

func Test_receiveMessage_receiveSigMessageAndStoresTheirKeyIDAndTheirCurrentDHPubKey(t *testing.T) {
	var nilBigInt *big.Int

	c := bobContextAtAwaitingSig()

	msg := fixtureSigMsg(otrV2{})
	assertEquals(t, c.msgState, plainText)

	_, err := c.receiveAKE(msg)

	assertEquals(t, err, nil)
	assertEquals(t, c.keys.theirKeyID, uint32(1))
	assertDeepEquals(t, c.keys.theirCurrentDHPubKey, fixedgy)
	assertEquals(t, c.keys.theirPreviousDHPubKey, nilBigInt)
}

func Test_authStateAwaitingDHKey_receiveDHKeyMessage_returnsErrorIfprocessDHKeyReturnsError(t *testing.T) {
	ourDHCommitAKE := fixtureConversation()
	ourDHCommitAKE.dhCommitMessage()

	c := newConversation(otrV3{}, fixtureRand())
	c.startAKE()
	c.setSecretExponent(ourDHCommitAKE.ake.secretExponent)
	c.ourKey = bobPrivateKey

	_, _, err := authStateAwaitingDHKey{}.receiveDHKeyMessage(c, []byte{0x01, 0x02})

	assertEquals(t, err, errInvalidOTRMessage)
}

func Test_authStateAwaitingDHKey_receiveDHKeyMessage_returnsErrorIfrevealSigMessageReturnsError(t *testing.T) {
	ourDHCommitAKE := fixtureConversation()
	ourDHCommitAKE.dhCommitMessage()

	c := newConversation(otrV3{}, fixedRand([]string{"ABCD"}))
	c.startAKE()
	c.setSecretExponent(ourDHCommitAKE.ake.secretExponent)
	c.ourKey = bobPrivateKey

	sameDHKeyMsg := fixtureDHKeyMsg(otrV3{})
	_, _, err := authStateAwaitingDHKey{}.receiveDHKeyMessage(c, sameDHKeyMsg)

	assertEquals(t, err, errShortRandomRead)
}

func Test_authStateAwaitingSig_receiveDHKeyMessage_returnsErrorIfprocessDHKeyReturnsError(t *testing.T) {
	ourDHCommitAKE := fixtureConversation()
	ourDHCommitAKE.dhCommitMessage()

	c := newConversation(otrV3{}, fixtureRand())
	c.startAKE()
	c.setSecretExponent(ourDHCommitAKE.ake.secretExponent)
	c.ourKey = bobPrivateKey

	_, _, err := authStateAwaitingSig{}.receiveDHKeyMessage(c, []byte{0x01, 0x02})

	assertEquals(t, err, errInvalidOTRMessage)
}

func Test_generateCommitMsgInstanceTags_returnsErrorIfMsgDoesntHaveMsgHeader(t *testing.T) {
	ake := fixtureConversation()
	err := generateCommitMsgInstanceTags(ake, []byte{0x00, 0x01})
	assertEquals(t, err, errInvalidOTRMessage)
}

func Test_generateCommitMsgInstanceTags_returnsErrorIfMsgIsntLongEnoughForInstanceTag(t *testing.T) {
	ake := fixtureConversation()
	err := generateCommitMsgInstanceTags(ake, []byte{0x00, 0x01, 0x02, 0x00, 0x00, 0x00})
	assertEquals(t, err, errInvalidOTRMessage)
}

func Test_authStateAwaitingRevealSig_receiveDHCommitMessage_returnsErrorIfProcessDHCommitOrGenerateCommitInstanceTagsFailsFails(t *testing.T) {
	ourDHCommitAKE := fixtureConversation()
	ourDHCommitAKE.dhCommitMessage()

	c := newConversation(otrV3{}, fixtureRand())
	c.startAKE()
	c.ake.theirPublicValue = ourDHCommitAKE.ake.ourPublicValue

	_, _, err := authStateAwaitingRevealSig{}.receiveDHCommitMessage(c, []byte{0x00, 0x00})
	assertEquals(t, err, errInvalidOTRMessage)
}

func Test_authStateNone_receiveDHCommitMessage_returnsErrorIfgenerateCommitMsgInstanceTagsFails(t *testing.T) {
	ourDHCommitAKE := fixtureConversation()
	ourDHCommitAKE.dhCommitMessage()

	c := newConversation(otrV3{}, fixtureRand())
	c.startAKE()
	c.ake.theirPublicValue = ourDHCommitAKE.ake.ourPublicValue

	_, _, err := authStateNone{}.receiveDHCommitMessage(c, []byte{0x00, 0x00})
	assertEquals(t, err, errInvalidOTRMessage)
}

func Test_authStateNone_receiveDHCommitMessage_returnsErrorIfdhKeyMessageFails(t *testing.T) {
	ourDHCommitAKE := fixtureConversation()
	ourDHCommitAKE.dhCommitMessage()

	c := newConversation(otrV2{}, fixedRand([]string{"ABCD"}))
	c.startAKE()
	c.ake.theirPublicValue = ourDHCommitAKE.ake.ourPublicValue

	_, _, err := authStateNone{}.receiveDHCommitMessage(c, []byte{0x00, 0x00})
	assertEquals(t, err, errShortRandomRead)
}

func Test_authStateNone_receiveDHCommitMessage_returnsErrorIfProcessDHCommitFails(t *testing.T) {
	ourDHCommitAKE := fixtureConversation()
	ourDHCommitAKE.dhCommitMessage()

	c := newConversation(otrV2{}, fixtureRand())
	c.startAKE()
	c.ake.theirPublicValue = ourDHCommitAKE.ake.ourPublicValue

	_, _, err := authStateNone{}.receiveDHCommitMessage(c, []byte{0x00, 0x00})
	assertEquals(t, err, errInvalidOTRMessage)
}

func Test_authStateNone_receiveQueryMessage_returnsNoErrorForValidMessage(t *testing.T) {
	c := newConversation(otrV3{}, fixtureRand())
	c.policies.add(allowV3)
	_, err := c.receiveQueryMessage([]byte("?OTRv3?"))
	assertEquals(t, err, nil)
}

func Test_authStateNone_receiveQueryMessage_returnsErrorIfNoCompatibleVersionCouldBeFound(t *testing.T) {
	c := newConversation(otrV3{}, fixtureRand())
	c.policies.add(allowV3)
	_, err := c.receiveQueryMessage([]byte("?OTRv2?"))
	assertEquals(t, err, errInvalidVersion)
}

func Test_authStateNone_receiveQueryMessage_returnsErrorIfDhCommitMessageGeneratesError(t *testing.T) {
	c := newConversation(otrV2{}, fixedRand([]string{"ABCDABCD"}))
	c.policies.add(allowV2)
	_, err := c.receiveQueryMessage([]byte("?OTRv2?"))
	assertEquals(t, err, errShortRandomRead)
}

func Test_authStateAwaitingDHKey_receiveDHCommitMessage_failsIfMsgDoesntHaveHeader(t *testing.T) {
	ourDHCommitAKE := fixtureConversation()
	ourDHCommitAKE.dhCommitMessage()

	c := newConversation(otrV2{}, fixtureRand())
	c.startAKE()
	c.ake.theirPublicValue = ourDHCommitAKE.ake.ourPublicValue

	_, _, err := authStateAwaitingDHKey{}.receiveDHCommitMessage(c, []byte{0x00, 0x00})
	assertEquals(t, err, errInvalidOTRMessage)
}

func Test_authStateAwaitingDHKey_receiveDHCommitMessage_failsIfCantExtractFirstPart(t *testing.T) {
	ourDHCommitAKE := fixtureConversation()
	ourDHCommitAKE.dhCommitMessage()

	c := newConversation(otrV2{}, fixtureRand())
	c.startAKE()
	c.ake.theirPublicValue = ourDHCommitAKE.ake.ourPublicValue

	_, _, err := authStateAwaitingDHKey{}.receiveDHCommitMessage(c, []byte{0x00, 0x00, 0x00, 0x01})
	assertEquals(t, err, errInvalidOTRMessage)
}

func Test_authStateAwaitingDHKey_receiveDHCommitMessage_failsIfCantExtractSecondPart(t *testing.T) {
	ourDHCommitAKE := fixtureConversation()
	ourDHCommitAKE.dhCommitMessage()

	c := newConversation(otrV2{}, fixtureRand())
	c.startAKE()
	c.ake.theirPublicValue = ourDHCommitAKE.ake.ourPublicValue

	_, _, err := authStateAwaitingDHKey{}.receiveDHCommitMessage(c, []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x01, 0x00, 0x01, 0x02})
	assertEquals(t, err, errInvalidOTRMessage)
}
