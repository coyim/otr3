package otr3

import (
	"crypto/sha256"
	"math/big"
	"testing"
)

func Test_conversationInitialState(t *testing.T) {
	c := newConversation(nil, fixtureRand())
	assertEquals(t, c.ake.state, authStateNone{})
}

func Test_receiveDHCommit_TransitionsFromNoneToAwaitingRevealSigAndSendDHKeyMsg(t *testing.T) {
	c := newConversation(otrV3{}, fixtureRand())
	nextState, nextMsg, e := authStateNone{}.receiveDHCommitMessage(c, fixtureDHCommitMsgBody())

	assertEquals(t, e, nil)
	assertEquals(t, nextState, authStateAwaitingRevealSig{})
	assertEquals(t, dhMsgType(nextMsg), msgTypeDHKey)
}

func Test_receiveDHCommit_AtAuthStateNoneStoresGyAndY(t *testing.T) {
	c := newConversation(otrV3{}, fixtureRand())
	authStateNone{}.receiveDHCommitMessage(c, fixtureDHCommitMsg())

	assertDeepEquals(t, c.ake.ourPublicValue, fixedgy)
	assertDeepEquals(t, c.ake.secretExponent, fixedy)
}

func Test_receiveDHCommit_AtAuthStateNoneStoresEncryptedGxAndHashedGx(t *testing.T) {
	c := newConversation(otrV3{}, fixtureRand())

	dhCommitMsg := fixtureDHCommitMsgBody()
	newMsg, encryptedGx, _ := extractData(dhCommitMsg)
	_, hashedGx, _ := extractData(newMsg)

	authStateNone{}.receiveDHCommitMessage(c, dhCommitMsg)

	assertDeepEquals(t, c.ake.hashedGx[:], hashedGx)
	assertDeepEquals(t, c.ake.encryptedGx, encryptedGx)
}

func Test_receiveDHCommit_ResendPreviousDHKeyMsgFromAwaitingRevealSig(t *testing.T) {
	c := newConversation(otrV3{}, fixtureRand())

	authAwaitingRevSig, prevDHKeyMsg, _ := authStateNone{}.receiveDHCommitMessage(c, fixtureDHCommitMsgBody())
	assertEquals(t, authAwaitingRevSig, authStateAwaitingRevealSig{})

	nextState, msg, _ := authAwaitingRevSig.receiveDHCommitMessage(c, fixtureDHCommitMsgBody())

	assertEquals(t, nextState, authStateAwaitingRevealSig{})
	assertEquals(t, dhMsgType(msg), msgTypeDHKey)
	assertDeepEquals(t, prevDHKeyMsg, msg)
}

func Test_receiveDHCommit_AtAuthAwaitingRevealSigiForgetOldEncryptedGxAndHashedGx(t *testing.T) {
	c := newConversation(otrV3{}, fixtureRand())
	c.ake.encryptedGx = []byte{0x02}         //some encryptedGx
	c.ake.hashedGx = [sha256.Size]byte{0x05} //some hashedGx

	newDHCommitMsg := fixtureDHCommitMsgBody()
	newMsg, newEncryptedGx, _ := extractData(newDHCommitMsg)
	_, newHashedGx, _ := extractData(newMsg)

	authStateNone{}.receiveDHCommitMessage(c, fixtureDHCommitMsgBody())

	authStateAwaitingRevealSig{}.receiveDHCommitMessage(c, newDHCommitMsg)
	assertDeepEquals(t, c.ake.encryptedGx, newEncryptedGx)
	assertDeepEquals(t, c.ake.hashedGx[:], newHashedGx)
}

func Test_receiveDHCommit_AtAuthAwaitingSigTransitionsToAwaitingRevSigAndSendsNewDHKeyMsg(t *testing.T) {
	c := newConversation(otrV3{}, fixtureRand())

	authAwaitingRevSig, msg, _ := authStateAwaitingSig{}.receiveDHCommitMessage(c, fixtureDHCommitMsgBody())
	assertEquals(t, authAwaitingRevSig, authStateAwaitingRevealSig{})
	assertEquals(t, dhMsgType(msg), msgTypeDHKey)
}

func Test_receiveDHCommit_AtAwaitingDHKeyIgnoreIncomingMsgAndResendOurDHCommitMsgIfOurHashIsHigher(t *testing.T) {
	ourDHCommitAKE := fixtureConversation()
	ourDHMsg, _ := ourDHCommitAKE.dhCommitMessage()
	ourDHMsg, _ = ourDHCommitAKE.wrapMessageHeader(msgTypeDHCommit, ourDHMsg)

	//make sure we store the same values when creating the DH commit
	c := newConversation(otrV3{}, fixtureRand())
	c.initAKE()
	c.ake.encryptedGx = ourDHCommitAKE.ake.encryptedGx
	c.ake.theirPublicValue = ourDHCommitAKE.ake.ourPublicValue

	// force their hashedGx to be lower than ours
	msg := fixtureDHCommitMsgBody()
	newPoint, _, _ := extractData(msg)
	newPoint[4] = 0x00

	state, newMsg, err := authStateAwaitingDHKey{}.receiveDHCommitMessage(c, msg)
	assertDeepEquals(t, err, nil)
	assertEquals(t, state, authStateAwaitingRevealSig{})
	assertDeepEquals(t, newMsg, ourDHMsg)
}

func Test_receiveDHCommit_AtAwaitingDHKeyForgetOurGxAndSendDHKeyMsgAndGoToAwaitingRevealSig(t *testing.T) {
	ourDHCommitAKE := fixtureConversation()
	ourDHCommitAKE.dhCommitMessage()

	//make sure we store the same values when creating the DH commit
	c := newConversation(otrV3{}, fixtureRand())
	c.initAKE()
	c.ake.theirPublicValue = ourDHCommitAKE.ake.ourPublicValue

	// force their hashedGx to be higher than ours
	msg := fixtureDHCommitMsgBody()
	newPoint, _, _ := extractData(msg)
	newPoint[4] = 0xFF

	state, newMsg, err := authStateAwaitingDHKey{}.receiveDHCommitMessage(c, msg)
	assertDeepEquals(t, err, nil)
	assertEquals(t, state, authStateAwaitingRevealSig{})
	assertEquals(t, dhMsgType(newMsg), msgTypeDHKey)
	assertDeepEquals(t, c.ake.ourPublicValue, fixedgy)
	assertDeepEquals(t, c.ake.secretExponent, fixedy)
}

func Test_receiveDHKey_AtAuthStateNoneOrAuthStateAwaitingRevealSigIgnoreIt(t *testing.T) {
	var nilB []byte
	c := newConversation(otrV3{}, fixtureRand())
	c.initAKE()
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

	state, msg, _ := authStateAwaitingDHKey{}.receiveDHKeyMessage(c, fixtureDHKeyMsg(otrV3{})[otrv3HeaderLen:])

	_, ok := state.(authStateAwaitingSig)
	assertEquals(t, ok, true)
	assertEquals(t, dhMsgType(msg), msgTypeRevealSig)
	assertEquals(t, dhMsgVersion(msg), uint16(3))
}

func Test_receiveDHKey_AtAwaitingDHKeyStoresGyAndSigKey(t *testing.T) {
	ourDHCommitAKE := fixtureConversation()
	ourDHCommitAKE.dhCommitMessage()

	c := bobContextAtAwaitingDHKey()

	_, _, err := authStateAwaitingDHKey{}.receiveDHKeyMessage(c, fixtureDHKeyMsg(otrV3{})[otrv3HeaderLen:])

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

	_, _, err := authStateAwaitingDHKey{}.receiveDHKeyMessage(c, fixtureDHKeyMsg(otrV3{})[otrv3HeaderLen:])

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
	c.initAKE()
	c.setSecretExponent(ourDHCommitAKE.ake.secretExponent)
	c.OurKey = bobPrivateKey

	sameDHKeyMsg := fixtureDHKeyMsg(otrV3{})[otrv3HeaderLen:]
	sigState, previousRevealSig, _ := authStateAwaitingDHKey{}.receiveDHKeyMessage(c, sameDHKeyMsg)

	state, msg, _ := sigState.receiveDHKeyMessage(c, sameDHKeyMsg)

	//FIXME: What about gy and sigKey?
	_, sameStateType := state.(authStateAwaitingSig)
	assertDeepEquals(t, sameStateType, true)
	assertDeepEquals(t, msg, previousRevealSig)
}

func Test_receiveDHKey_AtAuthAwaitingSigIgnoresMsgIfIsNotSameDHKeyMsg(t *testing.T) {
	var nilB []byte

	newDHKeyMsg := fixtureDHKeyMsgBody(otrV3{})
	c := newConversation(otrV3{}, fixtureRand())
	c.initAKE()

	state, msg, _ := authStateAwaitingSig{}.receiveDHKeyMessage(c, newDHKeyMsg)

	_, sameStateType := state.(authStateAwaitingSig)
	assertDeepEquals(t, sameStateType, true)
	assertDeepEquals(t, msg, nilB)
}

func Test_receiveRevealSig_TransitionsFromAwaitingRevealSigToNoneOnSuccess(t *testing.T) {
	revealSignMsg := fixtureRevealSigMsgBody(otrV2{})

	c := aliceContextAtAwaitingRevealSig()

	state, msg, err := authStateAwaitingRevealSig{}.receiveRevealSigMessage(c, revealSignMsg)

	assertEquals(t, err, nil)
	assertEquals(t, state, authStateNone{})
	assertEquals(t, dhMsgType(msg), msgTypeSig)
}

func Test_receiveRevealSig_AtAwaitingRevealSigStoresOursAndTheirDHKeysAndIncreaseCounter(t *testing.T) {
	revealSignMsg := fixtureRevealSigMsgBody(otrV2{})

	c := aliceContextAtAwaitingRevealSig()

	_, _, err := authStateAwaitingRevealSig{}.receiveRevealSigMessage(c, revealSignMsg)

	assertNil(t, err)
	assertDeepEquals(t, c.keys.theirCurrentDHPubKey, fixedgx)
	assertNil(t, c.keys.theirPreviousDHPubKey)
	assertDeepEquals(t, c.keys.ourPreviousDHKeys.pub, fixedgy)
	assertDeepEquals(t, c.keys.ourPreviousDHKeys.priv, fixedy)
	assertEquals(t, c.keys.ourCounter, uint64(1))
	assertEquals(t, c.keys.ourKeyID, uint32(2))
	assertEquals(t, c.keys.theirKeyID, uint32(1))
}

func Test_authStateAwaitingRevealSig_receiveRevealSigMessage_returnsErrorIfProcessRevealSigFails(t *testing.T) {
	c := newConversation(otrV2{}, fixtureRand())
	c.Policies.add(allowV2)
	_, _, err := authStateAwaitingRevealSig{}.receiveRevealSigMessage(c, []byte{0x00, 0x00})
	assertDeepEquals(t, err, newOtrError("corrupt reveal signature message"))
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
	sigMsg := fixtureSigMsg(otrV2{})[otrv2HeaderLen:]
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

	revealSignMsg := fixtureRevealSigMsg(otrV2{})[otrv2HeaderLen:]

	for _, s := range states {
		c := newConversation(otrV3{}, fixtureRand())
		state, msg, err := s.receiveSigMessage(c, revealSignMsg)

		assertEquals(t, err, nil)
		assertEquals(t, state, s)
		assertDeepEquals(t, msg, nilB)
	}
}

func Test_receiveAKE_ignoresDHCommitIfItsVersionIsNotInThePolicy(t *testing.T) {
	cV2 := newConversation(otrV2{}, fixtureRand())
	cV2.Policies.add(allowV2)

	cV3 := newConversation(otrV3{}, fixtureRand())
	cV3.Policies.add(allowV3)

	ake := fixtureConversationV2()
	msgV2, _ := ake.dhCommitMessage()
	msgV3 := fixtureDHCommitMsgBody()

	_, toSend, _, _ := cV2.receiveDecoded(msgV3)
	assertEquals(t, cV2.ake.state, authStateNone{})
	assertNil(t, toSend)

	_, toSend, _, _ = cV3.receiveDecoded(msgV2[otrv3HeaderLen:])
	assertEquals(t, cV3.ake.state, authStateNone{})
	assertNil(t, toSend)
}

func Test_receiveDecoded_resolveProtocolVersionFromDHCommitMessage(t *testing.T) {
	c := newConversation(nil, fixtureRand())
	c.Policies = policies(allowV3)
	c.receiveDecoded(fixtureDHCommitMsg())

	assertEquals(t, c.version, otrV3{})

	c = newConversation(nil, fixtureRand())
	c.Policies = policies(allowV2)
	c.receiveDecoded(fixtureDHCommitMsgV2())

	assertEquals(t, c.version, otrV2{})
}

func Test_receiveAKE_ignoresDHKeyIfItsVersionIsNotInThePolicy(t *testing.T) {
	cV2 := newConversation(otrV2{}, fixtureRand())
	cV2.ensureAKE()
	cV2.ake.state = authStateAwaitingDHKey{}
	cV2.Policies.add(allowV2)

	cV3 := newConversation(otrV3{}, fixtureRand())
	cV3.ensureAKE()
	cV3.ake.state = authStateAwaitingDHKey{}
	cV3.Policies.add(allowV3)

	msgV2 := fixtureDHKeyMsg(otrV2{})[otrv2HeaderLen:]
	msgV3 := fixtureDHKeyMsg(otrV3{})[otrv3HeaderLen:]

	_, toSend, _, _ := cV2.receiveDecoded(msgV3)
	assertEquals(t, cV2.ake.state, authStateAwaitingDHKey{})
	assertNil(t, toSend)

	_, toSend, _, _ = cV3.receiveDecoded(msgV2)
	assertEquals(t, cV3.ake.state, authStateAwaitingDHKey{})
	assertNil(t, toSend)
}

func Test_receiveAKE_ignoresRevealSigIfItsVersionIsNotInThePolicy(t *testing.T) {
	cV2 := newConversation(otrV2{}, fixtureRand())
	cV2.ensureAKE()
	cV2.ake.state = authStateAwaitingRevealSig{}
	cV2.Policies.add(allowV2)

	cV3 := newConversation(otrV3{}, fixtureRand())
	cV3.ensureAKE()
	cV3.ake.state = authStateAwaitingRevealSig{}
	cV3.Policies.add(allowV3)

	msgV2 := fixtureRevealSigMsg(otrV2{})
	msgV3 := fixtureRevealSigMsg(otrV3{})

	_, toSend, _, _ := cV2.receiveDecoded(msgV3)
	assertEquals(t, cV2.ake.state, authStateAwaitingRevealSig{})
	assertNil(t, toSend)

	_, toSend, _, _ = cV3.receiveDecoded(msgV2)
	assertEquals(t, cV3.ake.state, authStateAwaitingRevealSig{})
	assertNil(t, toSend)
}

func Test_receiveAKE_ignoresSignatureIfItsVersionIsNotInThePolicy(t *testing.T) {
	cV2 := newConversation(otrV2{}, fixtureRand())
	cV2.ensureAKE()
	cV2.ake.state = authStateAwaitingSig{}
	cV2.Policies.add(allowV2)

	cV3 := newConversation(otrV3{}, fixtureRand())
	cV3.ensureAKE()
	cV3.ake.state = authStateAwaitingSig{}
	cV3.Policies.add(allowV3)

	msgV2 := fixtureSigMsg(otrV2{})
	msgV3 := fixtureSigMsg(otrV3{})

	_, toSend, _, _ := cV2.receiveDecoded(msgV3)
	_, sameStateType := cV2.ake.state.(authStateAwaitingSig)
	assertDeepEquals(t, sameStateType, true)
	assertNil(t, toSend)

	_, toSend, _, _ = cV3.receiveDecoded(msgV2)
	_, sameStateType = cV3.ake.state.(authStateAwaitingSig)
	assertDeepEquals(t, sameStateType, true)
	assertNil(t, toSend)
}

func Test_receiveAKE_ignoresRevealSignaureIfDoesNotAllowV2(t *testing.T) {
	cV2 := newConversation(otrV2{}, fixtureRand())
	cV2.ensureAKE()
	cV2.ake.state = authStateAwaitingRevealSig{}
	cV2.Policies = policies(allowV3)

	cV3 := newConversation(otrV3{}, fixtureRand())
	cV3.ensureAKE()
	cV3.ake.state = authStateAwaitingRevealSig{}
	cV3.Policies = policies(allowV3)

	msgV2 := fixtureRevealSigMsg(otrV2{})[otrv2HeaderLen:]
	msgV3 := fixtureRevealSigMsg(otrV3{})[otrv3HeaderLen:]

	_, toSend, _, _ := cV3.receiveDecoded(msgV3)
	assertEquals(t, cV3.ake.state, authStateAwaitingRevealSig{})
	assertNil(t, toSend)

	_, toSend, _, _ = cV2.receiveDecoded(msgV2)
	assertEquals(t, cV2.ake.state, authStateAwaitingRevealSig{})
	assertNil(t, toSend)
}

func Test_receiveAKE_returnsErrorIfTheMessageIsCorrupt(t *testing.T) {
	cV3 := newConversation(otrV3{}, fixtureRand())
	cV3.ensureAKE()
	cV3.ake.state = authStateAwaitingSig{}
	cV3.Policies.add(allowV3)

	_, _, _, err := cV3.receiveDecoded([]byte{})
	assertEquals(t, err, errInvalidOTRMessage)

	_, _, _, err = cV3.receiveDecoded([]byte{0x00, 0x00})
	assertEquals(t, err, errWrongProtocolVersion)

	_, _, _, err = cV3.receiveDecoded([]byte{0x00, 0x03, 0x56, 0x00, 0x00, 0x01, 0x01, 0x00, 0x00, 0x01, 0x01})
	assertDeepEquals(t, err, newOtrError("unknown message type 0x56"))
}

func Test_receiveAKE_receiveRevealSigMessageAndSetMessageStateToEncrypted(t *testing.T) {
	c := aliceContextAtAwaitingRevealSig()
	msg := fixtureRevealSigMsg(otrV2{})
	assertEquals(t, c.msgState, plainText)

	_, _, _, err := c.receiveDecoded(msg)

	assertEquals(t, err, nil)
	assertEquals(t, c.msgState, encrypted)
}

func Test_receiveAKE_receiveRevealSigMessageAndStoresTheirKeyIDAndTheirCurrentDHPubKey(t *testing.T) {
	var nilBigInt *big.Int

	c := aliceContextAtAwaitingRevealSig()
	msg := fixtureRevealSigMsg(otrV2{})
	assertEquals(t, c.msgState, plainText)

	_, _, _, err := c.receiveDecoded(msg)

	assertEquals(t, err, nil)
	assertEquals(t, c.keys.theirKeyID, uint32(1))
	assertDeepEquals(t, c.keys.theirCurrentDHPubKey, fixedgx)
	assertEquals(t, c.keys.theirPreviousDHPubKey, nilBigInt)
}

func Test_receiveAKE_receiveSigMessageAndSetMessageStateToEncrypted(t *testing.T) {
	c := bobContextAtAwaitingSig()
	msg := fixtureSigMsg(otrV2{})
	assertEquals(t, c.msgState, plainText)

	_, _, _, err := c.receiveDecoded(msg)

	assertEquals(t, err, nil)
	assertEquals(t, c.msgState, encrypted)
}

func Test_receiveAKE_receiveSigMessageAndStoresTheirKeyIDAndTheirCurrentDHPubKey(t *testing.T) {
	var nilBigInt *big.Int

	c := bobContextAtAwaitingSig()

	msg := fixtureSigMsg(otrV2{})
	assertEquals(t, c.msgState, plainText)

	_, _, _, err := c.receiveDecoded(msg)

	assertEquals(t, err, nil)
	assertEquals(t, c.keys.theirKeyID, uint32(1))
	assertDeepEquals(t, c.keys.theirCurrentDHPubKey, fixedgy)
	assertEquals(t, c.keys.theirPreviousDHPubKey, nilBigInt)
}

func Test_authStateAwaitingDHKey_receiveDHKeyMessage_returnsErrorIfprocessDHKeyReturnsError(t *testing.T) {
	ourDHCommitAKE := fixtureConversation()
	ourDHCommitAKE.dhCommitMessage()

	c := newConversation(otrV3{}, fixtureRand())
	c.initAKE()
	c.setSecretExponent(ourDHCommitAKE.ake.secretExponent)
	c.OurKey = bobPrivateKey

	_, _, err := authStateAwaitingDHKey{}.receiveDHKeyMessage(c, []byte{0x00, 0x02})

	assertDeepEquals(t, err, newOtrError("corrupt DH key message"))
}

func Test_authStateAwaitingDHKey_receiveDHKeyMessage_returnsErrorIfrevealSigMessageReturnsError(t *testing.T) {
	ourDHCommitAKE := fixtureConversation()
	ourDHCommitAKE.dhCommitMessage()

	c := newConversation(otrV3{}, fixedRand([]string{"ABCD"}))
	c.initAKE()
	c.setSecretExponent(ourDHCommitAKE.ake.secretExponent)
	c.OurKey = bobPrivateKey

	sameDHKeyMsg := fixtureDHKeyMsgBody(otrV3{})
	_, _, err := authStateAwaitingDHKey{}.receiveDHKeyMessage(c, sameDHKeyMsg)

	assertEquals(t, err, errShortRandomRead)
}

func Test_authStateAwaitingSig_receiveDHKeyMessage_returnsErrorIfprocessDHKeyReturnsError(t *testing.T) {
	ourDHCommitAKE := fixtureConversation()
	ourDHCommitAKE.dhCommitMessage()

	c := newConversation(otrV3{}, fixtureRand())
	c.initAKE()
	c.setSecretExponent(ourDHCommitAKE.ake.secretExponent)
	c.OurKey = bobPrivateKey

	_, _, err := authStateAwaitingSig{}.receiveDHKeyMessage(c, []byte{0x01, 0x02})

	assertEquals(t, err, newOtrError("corrupt DH key message"))
}

func Test_authStateAwaitingSig_receiveSigMessage_returnsErrorIfProcessSigFails(t *testing.T) {
	c := newConversation(otrV2{}, fixtureRand())
	c.Policies.add(allowV2)
	_, _, err := authStateAwaitingSig{}.receiveSigMessage(c, []byte{0x00, 0x00})
	assertEquals(t, err, newOtrError("corrupt signature message"))
}

func Test_authStateAwaitingRevealSig_receiveDHCommitMessage_returnsErrorIfProcessDHCommitOrGenerateCommitInstanceTagsFailsFails(t *testing.T) {
	ourDHCommitAKE := fixtureConversation()
	ourDHCommitAKE.dhCommitMessage()

	c := newConversation(otrV3{}, fixtureRand())
	c.initAKE()
	c.ake.theirPublicValue = ourDHCommitAKE.ake.ourPublicValue

	_, _, err := authStateAwaitingRevealSig{}.receiveDHCommitMessage(c, []byte{0x00, 0x00})
	assertEquals(t, err, newOtrError("corrupt DH commit message"))
}

func Test_authStateNone_receiveDHCommitMessage_returnsErrorIfgenerateCommitMsgInstanceTagsFails(t *testing.T) {
	ourDHCommitAKE := fixtureConversation()
	ourDHCommitAKE.dhCommitMessage()

	c := newConversation(otrV3{}, fixtureRand())
	c.initAKE()
	c.ake.theirPublicValue = ourDHCommitAKE.ake.ourPublicValue

	_, _, err := authStateNone{}.receiveDHCommitMessage(c, []byte{0x00, 0x00})
	assertEquals(t, err, newOtrError("corrupt DH commit message"))
}

func Test_authStateNone_receiveDHCommitMessage_returnsErrorIfdhKeyMessageFails(t *testing.T) {
	ourDHCommitAKE := fixtureConversation()
	ourDHCommitAKE.dhCommitMessage()

	c := newConversation(otrV2{}, fixedRand([]string{"ABCD"}))
	c.initAKE()
	c.ake.theirPublicValue = ourDHCommitAKE.ake.ourPublicValue

	_, _, err := authStateNone{}.receiveDHCommitMessage(c, []byte{0x00, 0x00, 0x00})
	assertEquals(t, err, errShortRandomRead)
}

func Test_authStateNone_receiveDHCommitMessage_returnsErrorIfProcessDHCommitFails(t *testing.T) {
	ourDHCommitAKE := fixtureConversation()
	ourDHCommitAKE.dhCommitMessage()

	c := newConversation(otrV2{}, fixtureRand())
	c.initAKE()
	c.ake.theirPublicValue = ourDHCommitAKE.ake.ourPublicValue

	_, _, err := authStateNone{}.receiveDHCommitMessage(c, []byte{0x00, 0x00})
	assertEquals(t, err, newOtrError("corrupt DH commit message"))
}

func Test_authStateNone_receiveQueryMessage_returnsNoErrorForValidMessage(t *testing.T) {
	c := newConversation(otrV3{}, fixtureRand())
	c.Policies.add(allowV3)
	_, err := c.receiveQueryMessage([]byte("?OTRv3?"))
	assertEquals(t, err, nil)
}

func Test_authStateNone_receiveQueryMessage_returnsErrorIfNoCompatibleVersionCouldBeFound(t *testing.T) {
	c := newConversation(otrV3{}, fixtureRand())
	c.Policies.add(allowV3)
	_, err := c.receiveQueryMessage([]byte("?OTRv2?"))
	assertEquals(t, err, errInvalidVersion)
}

func Test_authStateNone_receiveQueryMessage_returnsErrorIfDhCommitMessageGeneratesError(t *testing.T) {
	c := newConversation(otrV2{}, fixedRand([]string{"ABCDABCD"}))
	c.Policies.add(allowV2)
	_, err := c.receiveQueryMessage([]byte("?OTRv2?"))
	assertEquals(t, err, errShortRandomRead)
}

func Test_authStateAwaitingDHKey_receiveDHCommitMessage_failsIfMsgDoesntHaveHeader(t *testing.T) {
	ourDHCommitAKE := fixtureConversation()
	ourDHCommitAKE.dhCommitMessage()

	c := newConversation(otrV2{}, fixtureRand())
	c.initAKE()
	c.ake.theirPublicValue = ourDHCommitAKE.ake.ourPublicValue

	_, _, err := authStateAwaitingDHKey{}.receiveDHCommitMessage(c, []byte{0x00, 0x00})
	assertEquals(t, err, errInvalidOTRMessage)
}

func Test_authStateAwaitingDHKey_receiveDHCommitMessage_failsIfCantExtractFirstPart(t *testing.T) {
	ourDHCommitAKE := fixtureConversation()
	ourDHCommitAKE.dhCommitMessage()

	c := newConversation(otrV2{}, fixtureRand())
	c.initAKE()
	c.ake.theirPublicValue = ourDHCommitAKE.ake.ourPublicValue

	_, _, err := authStateAwaitingDHKey{}.receiveDHCommitMessage(c, []byte{0x00, 0x00, 0x00, 0x01})
	assertEquals(t, err, errInvalidOTRMessage)
}

func Test_authStateAwaitingDHKey_receiveDHCommitMessage_failsIfCantExtractSecondPart(t *testing.T) {
	ourDHCommitAKE := fixtureConversation()
	ourDHCommitAKE.dhCommitMessage()

	c := newConversation(otrV2{}, fixtureRand())
	c.initAKE()
	c.ake.theirPublicValue = ourDHCommitAKE.ake.ourPublicValue

	_, _, err := authStateAwaitingDHKey{}.receiveDHCommitMessage(c, []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x01, 0x00, 0x01, 0x02})
	assertEquals(t, err, errInvalidOTRMessage)
}

func Test_authStateNone_String_returnsTheCorrectString(t *testing.T) {
	assertEquals(t, authStateNone{}.String(), "AUTHSTATE_NONE")
}

func Test_authStateAwaitingDHKey_String_returnsTheCorrectString(t *testing.T) {
	assertEquals(t, authStateAwaitingDHKey{}.String(), "AUTHSTATE_AWAITING_DHKEY")
}

func Test_authStateAwaitingRevealSig_String_returnsTheCorrectString(t *testing.T) {
	assertEquals(t, authStateAwaitingRevealSig{}.String(), "AUTHSTATE_AWAITING_REVEALSIG")
}

func Test_authStateAwaitingSig_String_returnsTheCorrectString(t *testing.T) {
	assertEquals(t, authStateAwaitingSig{}.String(), "AUTHSTATE_AWAITING_SIG")
}

func Test_authStateV1Setup_String_returnsTheCorrectString(t *testing.T) {
	assertEquals(t, authStateV1Setup{}.String(), "AUTHSTATE_V1_SETUP")
}
