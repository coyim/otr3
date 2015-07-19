package otr3

import (
	"crypto/sha256"
	"io"
	"testing"
)

func dhMsgType(msg []byte) byte {
	return msg[2]
}

func newAkeContext(v otrVersion, r io.Reader) akeContext {
	return akeContext{
		otrContext: newOtrContext(v, r),
		authState:  authStateNone{},
		policies:   0,
	}
}

func fixtureAKE() AKE {
	return fixtureAKEWithVersion(otrV3{})
}

func fixtureAKEV2() AKE {
	return fixtureAKEWithVersion(otrV2{})
}

func fixtureAKEWithVersion(v otrVersion) AKE {
	return AKE{
		akeContext: newAkeContext(v, fixtureRand()),
	}
}

func fixtureDHCommitMsg() []byte {
	ake := fixtureAKE()
	ake.senderInstanceTag = generateIntanceTag()
	msg, _ := ake.dhCommitMessage()
	return msg
}

func fixtureDHKeyMsg(v otrVersion) []byte {
	ake := fixtureAKEWithVersion(v)
	ake.ourKey = alicePrivateKey
	msg, _ := ake.dhKeyMessage()
	return msg
}

func fixtureRevealSigMsg() []byte {
	ake := fixtureAKEWithVersion(nil)
	ake.akeContext = bobContextAtReceiveDHKey()

	//revealSig is V2 only
	ake.otrVersion = otrV2{}
	ake.addPolicy(allowV2)

	msg, _ := ake.revealSigMessage()

	return msg
}

func fixtureSigMsg() []byte {
	ake := fixtureAKEWithVersion(otrV2{})
	ake.akeContext = aliceContextAtReceiveRevealSig()

	msg, _ := ake.sigMessage()

	return msg
}

func bobContextAtAwaitingSig() akeContext {
	c := bobContextAtReceiveDHKey()
	c.otrVersion = otrV2{}
	c.addPolicy(allowV2)

	return c
}

func bobContextAtReceiveDHKey() akeContext {
	c := bobContextAtAwaitingDHKey()
	c.gy = fixedgy // stored at receiveDHKey

	copy(c.sigKey.c[:], bytesFromHex("d942cc80b66503414c05e3752d9ba5c4"))
	copy(c.sigKey.m1[:], bytesFromHex("b6254b8eab0ad98152949454d23c8c9b08e4e9cf423b27edc09b1975a76eb59c"))
	copy(c.sigKey.m2[:], bytesFromHex("954be27015eeb0455250144d906e83e7d329c49581aea634c4189a3c981184f5"))

	return c
}

func bobContextAtAwaitingDHKey() akeContext {
	c := newAkeContext(otrV3{}, fixtureRand())
	c.addPolicy(allowV3)
	c.authState = authStateAwaitingDHKey{}
	c.ourKey = bobPrivateKey

	copy(c.r[:], fixedr) // stored at sendDHCommit
	c.x = fixedx         // stored at sendDHCommit
	c.gx = fixedgx       // stored at sendDHCommit

	return c
}

func aliceContextAtReceiveRevealSig() akeContext {
	c := aliceContextAtAwaitingRevealSig()
	c.gx = fixedgx // Alice decrypts encryptedGx using r

	return c
}

func aliceContextAtAwaitingRevealSig() akeContext {
	c := newAkeContext(otrV2{}, fixtureRand())
	c.addPolicy(allowV2)
	c.authState = authStateAwaitingRevealSig{}
	c.ourKey = alicePrivateKey

	copy(c.hashedGx[:], expectedHashedGxValue) //stored at receiveDHCommit
	c.encryptedGx = expectedEncryptedGxValue   //stored at receiveDHCommit

	c.gy = fixedgy //stored at sendDHKey
	c.y = fixedy   //stored at sendDHKey

	return c
}

func Test_receiveQueryMessage_SendDHCommitAndTransitToStateAwaitingDHKey(t *testing.T) {
	states := []authState{
		authStateNone{},
		authStateAwaitingDHKey{},
		authStateAwaitingRevealSig{},
		authStateAwaitingSig{},
	}

	queryMsg := []byte("?OTRv3?")

	for _, s := range states {
		c := newAkeContext(nil, fixtureRand())
		c.addPolicy(allowV3)
		state, msg := s.receiveQueryMessage(&c, queryMsg)

		assertEquals(t, state, authStateAwaitingDHKey{})
		assertDeepEquals(t, fixtureDHCommitMsg(), msg)
	}
}

func Test_receiveQueryMessage_StoresXAndGx(t *testing.T) {
	fixture := fixtureAKE()
	fixture.dhCommitMessage()

	msg := []byte("?OTRv3?")
	cxt := newAkeContext(nil, fixtureRand())
	cxt.addPolicy(allowV3)

	cxt.receiveQueryMessage(msg)
	assertDeepEquals(t, cxt.x, fixture.x)
	assertDeepEquals(t, cxt.gx, fixture.gx)
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
		assertDeepEquals(t, authStateNone{}.parseOTRQueryMessage(m), versions)
	}
}

func Test_acceptOTRRequest_returnsNilForUnsupportedVersions(t *testing.T) {
	p := policies(0)
	msg := []byte("?OTR?")
	v := authStateNone{}.acceptOTRRequest(p, msg)

	assertEquals(t, v, nil)
}

func Test_acceptOTRRequest_acceptsOTRV3IfHasAllowV3Policy(t *testing.T) {
	msg := []byte("?OTRv32?")
	p := policies(0)
	p.allowV2()
	p.allowV3()
	v := authStateNone{}.acceptOTRRequest(p, msg)

	assertEquals(t, v, otrV3{})
}

func Test_acceptOTRRequest_acceptsOTRV2IfHasOnlyAllowV2Policy(t *testing.T) {
	msg := []byte("?OTRv32?")
	p := policies(0)
	p.allowV2()
	v := authStateNone{}.acceptOTRRequest(p, msg)

	assertEquals(t, v, otrV2{})
}

func Test_receiveDHCommit_TransitionsFromNoneToAwaitingRevealSigAndSendDHKeyMsg(t *testing.T) {
	c := newAkeContext(otrV3{}, fixtureRand())
	nextState, nextMsg := authStateNone{}.receiveDHCommitMessage(&c, fixtureDHCommitMsg())

	assertEquals(t, nextState, authStateAwaitingRevealSig{})
	assertEquals(t, dhMsgType(nextMsg), msgTypeDHKey)
}

func Test_receiveDHCommit_AtAuthStateNoneStoresGyAndY(t *testing.T) {
	c := newAkeContext(otrV3{}, fixtureRand())
	authStateNone{}.receiveDHCommitMessage(&c, fixtureDHCommitMsg())

	assertDeepEquals(t, c.gy, fixedgy)
	assertDeepEquals(t, c.y, fixedy)
}

func Test_receiveDHCommit_AtAuthStateNoneStoresEncryptedGxAndHashedGx(t *testing.T) {
	c := newAkeContext(otrV3{}, fixtureRand())

	dhCommitMsg := fixtureDHCommitMsg()
	newMsg, encryptedGx, _ := extractData(dhCommitMsg[c.headerLen():])
	_, hashedGx, _ := extractData(newMsg)

	authStateNone{}.receiveDHCommitMessage(&c, dhCommitMsg)

	assertDeepEquals(t, c.hashedGx[:], hashedGx)
	assertDeepEquals(t, c.encryptedGx, encryptedGx)
}

func Test_receiveDHCommit_ResendPreviousDHKeyMsgFromAwaitingRevealSig(t *testing.T) {
	c := newAkeContext(otrV3{}, fixtureRand())

	authAwaitingRevSig, prevDHKeyMsg := authStateNone{}.receiveDHCommitMessage(&c, fixtureDHCommitMsg())
	assertEquals(t, authAwaitingRevSig, authStateAwaitingRevealSig{})

	nextState, msg := authAwaitingRevSig.receiveDHCommitMessage(&c, fixtureDHCommitMsg())

	assertEquals(t, nextState, authStateAwaitingRevealSig{})
	assertEquals(t, dhMsgType(msg), msgTypeDHKey)
	assertDeepEquals(t, prevDHKeyMsg, msg)
}

func Test_receiveDHCommit_AtAuthAwaitingRevealSigiForgetOldEncryptedGxAndHashedGx(t *testing.T) {
	c := newAkeContext(otrV3{}, fixtureRand())
	//TODO needs to stores encryptedGx and hashedGx when it is generated
	c.encryptedGx = []byte{0x02}         //some encryptedGx
	c.hashedGx = [sha256.Size]byte{0x05} //some hashedGx

	newDHCommitMsg := fixtureDHCommitMsg()
	newMsg, newEncryptedGx, _ := extractData(newDHCommitMsg[c.headerLen():])
	_, newHashedGx, _ := extractData(newMsg)

	authStateNone{}.receiveDHCommitMessage(&c, fixtureDHCommitMsg())

	authStateAwaitingRevealSig{}.receiveDHCommitMessage(&c, newDHCommitMsg)
	assertDeepEquals(t, c.encryptedGx, newEncryptedGx)
	assertDeepEquals(t, c.hashedGx[:], newHashedGx)
}

func Test_receiveDHCommit_AtAuthAwaitingSigTransitionsToAwaitingRevSigAndSendsNewDHKeyMsg(t *testing.T) {
	c := newAkeContext(otrV3{}, fixtureRand())

	authAwaitingRevSig, msg := authStateAwaitingSig{}.receiveDHCommitMessage(&c, fixtureDHCommitMsg())
	assertEquals(t, authAwaitingRevSig, authStateAwaitingRevealSig{})
	assertEquals(t, dhMsgType(msg), msgTypeDHKey)
}

func Test_receiveDHCommit_AtAwaitingDHKeyIgnoreIncomingMsgAndResendOurDHCommitMsgIfOurHashIsHigher(t *testing.T) {
	ourDHCommitAKE := fixtureAKE()
	ourDHMsg, _ := ourDHCommitAKE.dhCommitMessage()

	//make sure we store the same alues when creating the DH commit
	c := newAkeContext(otrV3{}, fixtureRand())
	c.encryptedGx = ourDHCommitAKE.encryptedGx
	c.gx = ourDHCommitAKE.gx

	// force their hashedGx to be lower than ours
	msg := fixtureDHCommitMsg()
	newPoint, _, _ := extractData(msg[c.headerLen():])
	newPoint[4] = 0x00

	state, newMsg := authStateAwaitingDHKey{}.receiveDHCommitMessage(&c, msg)
	assertEquals(t, state, authStateAwaitingRevealSig{})
	assertDeepEquals(t, newMsg, ourDHMsg)
}

func Test_receiveDHCommit_AtAwaitingDHKeyForgetOurGxAndSendDHKeyMsgAndGoToAwaitingRevealSig(t *testing.T) {
	ourDHCommitAKE := fixtureAKE()
	ourDHCommitAKE.dhCommitMessage()

	//make sure we store the same values when creating the DH commit
	c := newAkeContext(otrV3{}, fixtureRand())
	c.gx = ourDHCommitAKE.gx

	// force their hashedGx to be higher than ours
	msg := fixtureDHCommitMsg()
	newPoint, _, _ := extractData(msg[c.headerLen():])
	newPoint[4] = 0xFF

	state, newMsg := authStateAwaitingDHKey{}.receiveDHCommitMessage(&c, msg)
	assertEquals(t, state, authStateAwaitingRevealSig{})
	assertDeepEquals(t, dhMsgType(newMsg), msgTypeDHKey)
	assertDeepEquals(t, c.gy, fixedgy)
	assertDeepEquals(t, c.y, fixedy)
}

func Test_receiveDHKey_AtAuthStateNoneOrAuthStateAwaitingRevealSigIgnoreIt(t *testing.T) {
	var nilB []byte
	c := newAkeContext(otrV3{}, fixtureRand())
	dhKeymsg := fixtureDHKeyMsg(otrV3{})

	states := []authState{
		authStateNone{},
		authStateAwaitingRevealSig{},
	}

	for _, s := range states {
		state, msg := s.receiveDHKeyMessage(&c, dhKeymsg)
		assertEquals(t, state, s)
		assertDeepEquals(t, msg, nilB)
	}
}

func Test_receiveDHKey_TransitionsFromAwaitingDHKeyToAwaitingSigAndSendsRevealSig(t *testing.T) {
	ourDHCommitAKE := fixtureAKE()
	ourDHCommitAKE.dhCommitMessage()

	c := bobContextAtAwaitingDHKey()

	state, msg := authStateAwaitingDHKey{}.receiveDHKeyMessage(&c, fixtureDHKeyMsg(otrV3{}))

	//TODO before generate rev si need to extract their gy from DH commit
	assertEquals(t, state, authStateAwaitingSig{})
	assertDeepEquals(t, dhMsgType(msg), msgTypeRevealSig)
}

func Test_receiveDHKey_AtAwaitingDHKeyStoresGyAndSigKey(t *testing.T) {
	ourDHCommitAKE := fixtureAKE()
	ourDHCommitAKE.dhCommitMessage()

	c := bobContextAtAwaitingDHKey()

	authStateAwaitingDHKey{}.receiveDHKeyMessage(&c, fixtureDHKeyMsg(otrV3{}))

	assertDeepEquals(t, c.gy, fixedgy)
	assertDeepEquals(t, c.sigKey.c[:], expectedC)
	assertDeepEquals(t, c.sigKey.m1[:], expectedM1)
	assertDeepEquals(t, c.sigKey.m2[:], expectedM2)
}

func Test_receiveDHKey_AtAuthAwaitingSigIfReceivesSameDHKeyMsgRetransmitRevealSigMsg(t *testing.T) {
	ourDHCommitAKE := fixtureAKE()
	ourDHCommitAKE.dhCommitMessage()

	c := newAkeContext(otrV3{}, fixtureRand())
	c.x = ourDHCommitAKE.x
	c.gx = ourDHCommitAKE.gx
	c.ourKey = bobPrivateKey

	sameDHKeyMsg := fixtureDHKeyMsg(otrV3{})
	sigState, previousRevealSig := authStateAwaitingDHKey{}.receiveDHKeyMessage(&c, sameDHKeyMsg)

	state, msg := sigState.receiveDHKeyMessage(&c, sameDHKeyMsg)

	//FIXME: What about gy and sigKey?
	assertEquals(t, state, authStateAwaitingSig{})
	assertDeepEquals(t, msg, previousRevealSig)
}

func Test_receiveDHKey_AtAuthAwaitingSigIgnoresMsgIfIsNotSameDHKeyMsg(t *testing.T) {
	var nilB []byte

	newDHKeyMsg := fixtureDHKeyMsg(otrV3{})
	c := newAkeContext(otrV3{}, fixtureRand())

	state, msg := authStateAwaitingSig{}.receiveDHKeyMessage(&c, newDHKeyMsg)

	assertEquals(t, state, authStateAwaitingSig{})
	assertDeepEquals(t, msg, nilB)
}

func Test_receiveRevealSig_TransitionsFromAwaitingRevealSigToNoneOnSuccess(t *testing.T) {
	revealSignMsg := fixtureRevealSigMsg()

	c := aliceContextAtAwaitingRevealSig()

	state, msg := authStateAwaitingRevealSig{}.receiveRevealSigMessage(&c, revealSignMsg)

	assertEquals(t, state, authStateNone{})
	assertDeepEquals(t, dhMsgType(msg), msgTypeSig)
}

func Test_receiveRevealSig_IgnoreMessageIfNotInStateAwaitingRevealSig(t *testing.T) {
	var nilB []byte

	states := []authState{
		authStateNone{},
		authStateAwaitingDHKey{},
		authStateAwaitingSig{},
	}

	revealSignMsg := fixtureRevealSigMsg()

	for _, s := range states {
		c := newAkeContext(otrV3{}, fixtureRand())
		state, msg := s.receiveRevealSigMessage(&c, revealSignMsg)

		assertEquals(t, state, s)
		assertDeepEquals(t, msg, nilB)
	}
}

func Test_receiveSig_TransitionsFromAwaitingSigToNoneOnSuccess(t *testing.T) {
	var nilB []byte
	sigMsg := fixtureSigMsg()
	c := bobContextAtAwaitingSig()

	state, msg := authStateAwaitingSig{}.receiveSigMessage(&c, sigMsg)

	assertEquals(t, state, authStateNone{})
	assertDeepEquals(t, msg, nilB)
}

func Test_receiveSig_IgnoreMessageIfNotInStateAwaitingSig(t *testing.T) {
	var nilB []byte

	states := []authState{
		authStateNone{},
		authStateAwaitingDHKey{},
		authStateAwaitingRevealSig{},
	}

	revealSignMsg := fixtureRevealSigMsg()

	for _, s := range states {
		c := newAkeContext(otrV3{}, fixtureRand())
		state, msg := s.receiveSigMessage(&c, revealSignMsg)

		assertEquals(t, state, s)
		assertDeepEquals(t, msg, nilB)
	}
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

func Test_receiveMessage_ignoresDHCommitIfItsVersionIsNotInThePolicy(t *testing.T) {
	var nilB []byte
	cV2 := newAkeContext(otrV2{}, fixtureRand())
	cV2.addPolicy(allowV2)

	cV3 := newAkeContext(otrV3{}, fixtureRand())
	cV3.addPolicy(allowV3)

	ake := fixtureAKEV2()
	msgV2, _ := ake.dhCommitMessage()
	msgV3 := fixtureDHCommitMsg()

	toSend := cV2.receiveMessage(msgV3)
	assertEquals(t, cV2.authState, authStateNone{})
	assertDeepEquals(t, toSend, nilB)

	toSend = cV3.receiveMessage(msgV2)
	assertEquals(t, cV3.authState, authStateNone{})
	assertDeepEquals(t, toSend, nilB)
}

func Test_receiveMessage_ignoresDHKeyIfItsVersionIsNotInThePolicy(t *testing.T) {
	var nilB []byte
	cV2 := newAkeContext(otrV2{}, fixtureRand())
	cV2.authState = authStateAwaitingDHKey{}
	cV2.addPolicy(allowV2)

	cV3 := newAkeContext(otrV3{}, fixtureRand())
	cV3.authState = authStateAwaitingDHKey{}
	cV3.addPolicy(allowV3)

	msgV2 := fixtureDHKeyMsg(otrV2{})
	msgV3 := fixtureDHKeyMsg(otrV3{})

	toSend := cV2.receiveMessage(msgV3)
	assertEquals(t, cV2.authState, authStateAwaitingDHKey{})
	assertDeepEquals(t, toSend, nilB)

	toSend = cV3.receiveMessage(msgV2)
	assertEquals(t, cV3.authState, authStateAwaitingDHKey{})
	assertDeepEquals(t, toSend, nilB)
}

func Test_receiveMessage_ignoresRevealSignaureIfDoesNotAllowV2(t *testing.T) {
	var nilB []byte
	cV3 := newAkeContext(otrV3{}, fixtureRand())
	cV3.authState = authStateAwaitingRevealSig{}
	cV3.addPolicy(allowV3)

	msg := fixtureRevealSigMsg()

	toSend := cV3.receiveMessage(msg)
	assertEquals(t, cV3.authState, authStateAwaitingRevealSig{})
	assertDeepEquals(t, toSend, nilB)
}

func Test_receiveMessage_ignoresSignaureIfDoesNotAllowV2(t *testing.T) {
	var nilB []byte
	cV3 := newAkeContext(otrV3{}, fixtureRand())
	cV3.authState = authStateAwaitingSig{}
	cV3.addPolicy(allowV3)

	msg := fixtureSigMsg()

	toSend := cV3.receiveMessage(msg)
	assertEquals(t, cV3.authState, authStateAwaitingSig{})
	assertDeepEquals(t, toSend, nilB)
}
