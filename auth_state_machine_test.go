package otr3

import (
	"crypto/sha256"
	"errors"
	"io"
	"math/big"
	"testing"
)

func dhMsgType(msg []byte) byte {
	return msg[2]
}

func newAkeContext(v otrVersion, r io.Reader) akeContext {
	return akeContext{
		otrContext: newOtrContext(v, r),
		authState:  authStateNone{},
		msgState:   0,
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
	ake.senderInstanceTag = generateInstanceTag()
	msg, _ := ake.dhCommitMessage()
	return msg
}

func fixtureDHKeyMsg(v otrVersion) []byte {
	ake := fixtureAKEWithVersion(v)
	ake.ourKey = alicePrivateKey
	msg, _ := ake.dhKeyMessage()
	return msg
}

func fixtureRevealSigMsg(v otrVersion) []byte {
	ake := fixtureAKEWithVersion(v)
	ake.akeContext = bobContextAtReceiveDHKey()
	ake.otrVersion = v

	msg, _ := ake.revealSigMessage()

	return msg
}

func fixtureSigMsg(v otrVersion) []byte {
	ake := fixtureAKEWithVersion(v)
	ake.akeContext = aliceContextAtReceiveRevealSig()
	ake.otrVersion = v

	msg, _ := ake.sigMessage()

	return msg
}

func bobContextAtAwaitingSig() akeContext {
	c := bobContextAtReceiveDHKey()
	c.otrVersion = otrV2{}
	c.addPolicy(allowV2)
	c.authState = authStateAwaitingSig{}

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
		state, msg, _ := s.receiveQueryMessage(&c, queryMsg)

		assertEquals(t, state, authStateAwaitingDHKey{})
		assertDeepEquals(t, fixtureDHCommitMsg(), msg)
	}
}

func Test_receiveQueryMessage_StoresRAndXAndGx(t *testing.T) {
	fixture := fixtureAKE()
	fixture.dhCommitMessage()

	msg := []byte("?OTRv3?")
	cxt := newAkeContext(nil, fixtureRand())
	cxt.addPolicy(allowV3)

	cxt.receiveQueryMessage(msg)
	assertDeepEquals(t, cxt.r, fixture.r)
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
	v, ok := authStateNone{}.acceptOTRRequest(p, msg)

	assertEquals(t, v, nil)
	assertEquals(t, ok, false)
}

func Test_acceptOTRRequest_acceptsOTRV3IfHasAllowV3Policy(t *testing.T) {
	msg := []byte("?OTRv32?")
	p := policies(0)
	p.allowV2()
	p.allowV3()
	v, ok := authStateNone{}.acceptOTRRequest(p, msg)

	assertEquals(t, v, otrV3{})
	assertEquals(t, ok, true)
}

func Test_acceptOTRRequest_acceptsOTRV2IfHasOnlyAllowV2Policy(t *testing.T) {
	msg := []byte("?OTRv32?")
	p := policies(0)
	p.allowV2()
	v, ok := authStateNone{}.acceptOTRRequest(p, msg)

	assertEquals(t, v, otrV2{})
	assertEquals(t, ok, true)
}

func Test_receiveDHCommit_TransitionsFromNoneToAwaitingRevealSigAndSendDHKeyMsg(t *testing.T) {
	c := newAkeContext(otrV3{}, fixtureRand())
	nextState, nextMsg, e := authStateNone{}.receiveDHCommitMessage(&c, fixtureDHCommitMsg())

	assertEquals(t, nextState, authStateAwaitingRevealSig{})
	assertEquals(t, dhMsgType(nextMsg), msgTypeDHKey)
	assertEquals(t, e, nil)
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

	authAwaitingRevSig, prevDHKeyMsg, _ := authStateNone{}.receiveDHCommitMessage(&c, fixtureDHCommitMsg())
	assertEquals(t, authAwaitingRevSig, authStateAwaitingRevealSig{})

	nextState, msg, _ := authAwaitingRevSig.receiveDHCommitMessage(&c, fixtureDHCommitMsg())

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

	authAwaitingRevSig, msg, _ := authStateAwaitingSig{}.receiveDHCommitMessage(&c, fixtureDHCommitMsg())
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

	state, newMsg, _ := authStateAwaitingDHKey{}.receiveDHCommitMessage(&c, msg)
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

	state, newMsg, _ := authStateAwaitingDHKey{}.receiveDHCommitMessage(&c, msg)
	assertEquals(t, state, authStateAwaitingRevealSig{})
	assertEquals(t, dhMsgType(newMsg), msgTypeDHKey)
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
		state, msg, err := s.receiveDHKeyMessage(&c, dhKeymsg)
		assertEquals(t, err, nil)
		assertEquals(t, state, s)
		assertDeepEquals(t, msg, nilB)
	}
}

func Test_receiveDHKey_TransitionsFromAwaitingDHKeyToAwaitingSigAndSendsRevealSig(t *testing.T) {
	ourDHCommitAKE := fixtureAKE()
	ourDHCommitAKE.dhCommitMessage()

	c := bobContextAtAwaitingDHKey()

	state, msg, _ := authStateAwaitingDHKey{}.receiveDHKeyMessage(&c, fixtureDHKeyMsg(otrV3{}))

	//TODO before generate rev si need to extract their gy from DH commit
	assertEquals(t, state, authStateAwaitingSig{})
	assertEquals(t, dhMsgType(msg), msgTypeRevealSig)
}

func Test_receiveDHKey_AtAwaitingDHKeyStoresGyAndSigKey(t *testing.T) {
	ourDHCommitAKE := fixtureAKE()
	ourDHCommitAKE.dhCommitMessage()

	c := bobContextAtAwaitingDHKey()

	_, _, err := authStateAwaitingDHKey{}.receiveDHKeyMessage(&c, fixtureDHKeyMsg(otrV3{}))

	assertEquals(t, err, nil)
	assertDeepEquals(t, c.gy, fixedgy)
	assertDeepEquals(t, c.sigKey.c[:], expectedC)
	assertDeepEquals(t, c.sigKey.m1[:], expectedM1)
	assertDeepEquals(t, c.sigKey.m2[:], expectedM2)
}

func Test_receiveDHKey_AtAwaitingDHKeyStoresOursAndTheirDHKeys(t *testing.T) {
	ourDHCommitAKE := fixtureAKE()
	ourDHCommitAKE.dhCommitMessage()

	c := bobContextAtAwaitingDHKey()

	_, _, err := authStateAwaitingDHKey{}.receiveDHKeyMessage(&c, fixtureDHKeyMsg(otrV3{}))

	assertEquals(t, err, nil)
	assertDeepEquals(t, c.theirCurrentDHPubKey, fixedgy)
	assertDeepEquals(t, c.ourCurrentDHKeys.pub, fixedgx)
	assertDeepEquals(t, c.ourCurrentDHKeys.priv, fixedx)
}

func Test_receiveDHKey_AtAuthAwaitingSigIfReceivesSameDHKeyMsgRetransmitRevealSigMsg(t *testing.T) {
	ourDHCommitAKE := fixtureAKE()
	ourDHCommitAKE.dhCommitMessage()

	c := newAkeContext(otrV3{}, fixtureRand())
	c.x = ourDHCommitAKE.x
	c.gx = ourDHCommitAKE.gx
	c.ourKey = bobPrivateKey

	sameDHKeyMsg := fixtureDHKeyMsg(otrV3{})
	sigState, previousRevealSig, _ := authStateAwaitingDHKey{}.receiveDHKeyMessage(&c, sameDHKeyMsg)

	state, msg, _ := sigState.receiveDHKeyMessage(&c, sameDHKeyMsg)

	//FIXME: What about gy and sigKey?
	assertEquals(t, state, authStateAwaitingSig{})
	assertDeepEquals(t, msg, previousRevealSig)
}

func Test_receiveDHKey_AtAuthAwaitingSigIgnoresMsgIfIsNotSameDHKeyMsg(t *testing.T) {
	var nilB []byte

	newDHKeyMsg := fixtureDHKeyMsg(otrV3{})
	c := newAkeContext(otrV3{}, fixtureRand())

	state, msg, _ := authStateAwaitingSig{}.receiveDHKeyMessage(&c, newDHKeyMsg)

	assertEquals(t, state, authStateAwaitingSig{})
	assertDeepEquals(t, msg, nilB)
}

func Test_receiveRevealSig_TransitionsFromAwaitingRevealSigToNoneOnSuccess(t *testing.T) {
	revealSignMsg := fixtureRevealSigMsg(otrV2{})

	c := aliceContextAtAwaitingRevealSig()

	state, msg, err := authStateAwaitingRevealSig{}.receiveRevealSigMessage(&c, revealSignMsg)

	assertEquals(t, err, nil)
	assertEquals(t, state, authStateNone{})
	assertEquals(t, dhMsgType(msg), msgTypeSig)
}

func Test_receiveRevealSig_AtAwaitingRevealSigStoresOursAndTheirDHKeys(t *testing.T) {
	var nilBigInt *big.Int
	revealSignMsg := fixtureRevealSigMsg(otrV2{})

	c := aliceContextAtAwaitingRevealSig()

	_, _, err := authStateAwaitingRevealSig{}.receiveRevealSigMessage(&c, revealSignMsg)

	assertEquals(t, err, nil)
	assertEquals(t, c.ourKeyID, uint32(0))
	assertEquals(t, c.theirKeyID, uint32(0)) //TODO create a fixture with a different value?
	assertDeepEquals(t, c.theirCurrentDHPubKey, fixedgx)
	assertDeepEquals(t, c.theirPreviousDHPubKey, nilBigInt)
	assertDeepEquals(t, c.ourCurrentDHKeys.pub, fixedgy)
	assertDeepEquals(t, c.ourCurrentDHKeys.priv, fixedy)
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
		c := newAkeContext(otrV3{}, fixtureRand())
		state, msg, err := s.receiveRevealSigMessage(&c, revealSignMsg)

		assertEquals(t, err, nil)
		assertEquals(t, state, s)
		assertDeepEquals(t, msg, nilB)
	}
}

func Test_receiveSig_TransitionsFromAwaitingSigToNoneOnSuccess(t *testing.T) {
	var nilB []byte
	sigMsg := fixtureSigMsg(otrV2{})
	c := bobContextAtAwaitingSig()

	state, msg, err := authStateAwaitingSig{}.receiveSigMessage(&c, sigMsg)

	assertEquals(t, err, nil)
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

	revealSignMsg := fixtureRevealSigMsg(otrV2{})

	for _, s := range states {
		c := newAkeContext(otrV3{}, fixtureRand())
		state, msg, err := s.receiveSigMessage(&c, revealSignMsg)

		assertEquals(t, err, nil)
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
	assertEquals(t, ake.senderInstanceTag, generateInstanceTag())
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

	toSend, _ := cV2.receiveMessage(msgV3)
	assertEquals(t, cV2.authState, authStateNone{})
	assertDeepEquals(t, toSend, nilB)

	toSend, _ = cV3.receiveMessage(msgV2)
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

	toSend, _ := cV2.receiveMessage(msgV3)
	assertEquals(t, cV2.authState, authStateAwaitingDHKey{})
	assertDeepEquals(t, toSend, nilB)

	toSend, _ = cV3.receiveMessage(msgV2)
	assertEquals(t, cV3.authState, authStateAwaitingDHKey{})
	assertDeepEquals(t, toSend, nilB)
}

func Test_receiveMessage_ignoresRevealSigIfItsVersionIsNotInThePolicy(t *testing.T) {
	var nilB []byte
	cV2 := newAkeContext(otrV2{}, fixtureRand())
	cV2.authState = authStateAwaitingRevealSig{}
	cV2.addPolicy(allowV2)

	cV3 := newAkeContext(otrV3{}, fixtureRand())
	cV3.authState = authStateAwaitingRevealSig{}
	cV3.addPolicy(allowV3)

	msgV2 := fixtureRevealSigMsg(otrV2{})
	msgV3 := fixtureRevealSigMsg(otrV3{})

	toSend, _ := cV2.receiveMessage(msgV3)
	assertEquals(t, cV2.authState, authStateAwaitingRevealSig{})
	assertDeepEquals(t, toSend, nilB)

	toSend, _ = cV3.receiveMessage(msgV2)
	assertEquals(t, cV3.authState, authStateAwaitingRevealSig{})
	assertDeepEquals(t, toSend, nilB)
}

func Test_receiveMessage_ignoresSignatureIfItsVersionIsNotInThePolicy(t *testing.T) {
	var nilB []byte
	cV2 := newAkeContext(otrV2{}, fixtureRand())
	cV2.authState = authStateAwaitingSig{}
	cV2.addPolicy(allowV2)

	cV3 := newAkeContext(otrV3{}, fixtureRand())
	cV3.authState = authStateAwaitingSig{}
	cV3.addPolicy(allowV3)

	msgV2 := fixtureSigMsg(otrV2{})
	msgV3 := fixtureSigMsg(otrV3{})

	toSend, _ := cV2.receiveMessage(msgV3)
	assertEquals(t, cV2.authState, authStateAwaitingSig{})
	assertDeepEquals(t, toSend, nilB)

	toSend, _ = cV3.receiveMessage(msgV2)
	assertEquals(t, cV3.authState, authStateAwaitingSig{})
	assertDeepEquals(t, toSend, nilB)
}

func Test_receiveMessage_ignoresRevealSignaureIfDoesNotAllowV2(t *testing.T) {
	var nilB []byte
	cV2 := newAkeContext(otrV2{}, fixtureRand())
	cV2.authState = authStateAwaitingRevealSig{}
	cV2.addPolicy(allowV3)

	cV3 := newAkeContext(otrV3{}, fixtureRand())
	cV3.authState = authStateAwaitingRevealSig{}
	cV3.addPolicy(allowV3)

	msgV2 := fixtureRevealSigMsg(otrV2{})
	msgV3 := fixtureRevealSigMsg(otrV3{})

	toSend, _ := cV3.receiveMessage(msgV3)
	assertEquals(t, cV3.authState, authStateAwaitingRevealSig{})
	assertDeepEquals(t, toSend, nilB)

	toSend, _ = cV2.receiveMessage(msgV2)
	assertEquals(t, cV2.authState, authStateAwaitingRevealSig{})
	assertDeepEquals(t, toSend, nilB)
}

func Test_receiveMessage_ignoresSignatureIfDoesNotAllowV2(t *testing.T) {
	var nilB []byte
	cV2 := newAkeContext(otrV2{}, fixtureRand())
	cV2.authState = authStateAwaitingSig{}
	cV2.addPolicy(allowV3)

	cV3 := newAkeContext(otrV3{}, fixtureRand())
	cV3.authState = authStateAwaitingSig{}
	cV3.addPolicy(allowV3)

	msgV2 := fixtureSigMsg(otrV2{})
	msgV3 := fixtureSigMsg(otrV3{})

	toSend, _ := cV3.receiveMessage(msgV3)
	assertEquals(t, cV3.authState, authStateAwaitingSig{})
	assertDeepEquals(t, toSend, nilB)

	toSend, _ = cV2.receiveMessage(msgV2)
	assertEquals(t, cV2.authState, authStateAwaitingSig{})
	assertDeepEquals(t, toSend, nilB)
}

func Test_receiveMessage_returnsErrorIfTheMessageIsCorrupt(t *testing.T) {
	cV3 := newAkeContext(otrV3{}, fixtureRand())
	cV3.authState = authStateAwaitingSig{}
	cV3.addPolicy(allowV3)

	_, err := cV3.receiveMessage([]byte{})
	assertEquals(t, err, errInvalidOTRMessage)

	_, err = cV3.receiveMessage([]byte{0x00, 0x00})
	assertEquals(t, err, errInvalidOTRMessage)

	_, err = cV3.receiveMessage([]byte{0x00, 0x03, 0x56})
	assertDeepEquals(t, err, errors.New("otr: unknown message type 0x56"))
}

func Test_authStateAwaitingSig_receiveSigMessage_returnsErrorIfProcessSigFails(t *testing.T) {
	c := newAkeContext(otrV2{}, fixtureRand())
	c.addPolicy(allowV2)
	_, _, err := authStateAwaitingSig{}.receiveSigMessage(&c, []byte{0x00, 0x00})
	assertEquals(t, err, errInvalidOTRMessage)
}

func Test_authStateAwaitingRevealSig_receiveRevealSigMessage_returnsErrorIfProcessRevealSigFails(t *testing.T) {
	c := newAkeContext(otrV2{}, fixtureRand())
	c.addPolicy(allowV2)
	_, _, err := authStateAwaitingRevealSig{}.receiveRevealSigMessage(&c, []byte{0x00, 0x00})
	assertEquals(t, err, errInvalidOTRMessage)
}

func Test_receiveMessage_receiveRevealSigMessageAndSetMessageStateToEncrypted(t *testing.T) {
	c := aliceContextAtAwaitingRevealSig()
	msg := fixtureRevealSigMsg(otrV2{})
	assertEquals(t, c.msgState, plainText)

	_, err := c.receiveMessage(msg)

	assertEquals(t, err, nil)
	assertEquals(t, c.msgState, encrypted)
}

func Test_receiveMessage_receiveRevealSigMessageAndStoresTheirKeyIDAndTheirCurrentDHPubKey(t *testing.T) {
	var nilBigInt *big.Int

	c := aliceContextAtAwaitingRevealSig()
	msg := fixtureRevealSigMsg(otrV2{})
	assertEquals(t, c.msgState, plainText)

	_, err := c.receiveMessage(msg)

	assertEquals(t, err, nil)
	assertEquals(t, c.theirKeyID, uint32(0)) // should not be 0
	assertDeepEquals(t, c.theirCurrentDHPubKey, fixedgx)
	assertEquals(t, c.theirPreviousDHPubKey, nilBigInt)
}

func Test_receiveMessage_receiveSigMessageAndSetMessageStateToEncrypted(t *testing.T) {
	c := bobContextAtAwaitingSig()
	msg := fixtureSigMsg(otrV2{})
	assertEquals(t, c.msgState, plainText)

	_, err := c.receiveMessage(msg)

	assertEquals(t, err, nil)
	assertEquals(t, c.msgState, encrypted)
}

//THUS
func Test_receiveMessage_receiveSigMessageAndStoresTheirKeyIDAndTheirCurrentDHPubKey(t *testing.T) {
	var nilBigInt *big.Int

	c := bobContextAtAwaitingSig()

	msg := fixtureSigMsg(otrV2{})
	assertEquals(t, c.msgState, plainText)

	_, err := c.receiveMessage(msg)

	assertEquals(t, err, nil)
	assertEquals(t, c.theirKeyID, uint32(0)) // should not be 0
	assertDeepEquals(t, c.theirCurrentDHPubKey, fixedgy)
	assertEquals(t, c.theirPreviousDHPubKey, nilBigInt)
}

func Test_authStateAwaitingDHKey_receiveDHKeyMessage_returnsErrorIfprocessDHKeyReturnsError(t *testing.T) {
	ourDHCommitAKE := fixtureAKE()
	ourDHCommitAKE.dhCommitMessage()

	c := newAkeContext(otrV3{}, fixtureRand())
	c.x = ourDHCommitAKE.x
	c.gx = ourDHCommitAKE.gx
	c.ourKey = bobPrivateKey

	_, _, err := authStateAwaitingDHKey{}.receiveDHKeyMessage(&c, []byte{0x01, 0x02})

	assertEquals(t, err, errInvalidOTRMessage)
}

func Test_authStateAwaitingDHKey_receiveDHKeyMessage_returnsErrorIfrevealSigMessageReturnsError(t *testing.T) {
	ourDHCommitAKE := fixtureAKE()
	ourDHCommitAKE.dhCommitMessage()

	c := newAkeContext(otrV3{}, fixedRand([]string{"ABCD"}))
	c.x = ourDHCommitAKE.x
	c.gx = ourDHCommitAKE.gx
	c.ourKey = bobPrivateKey

	sameDHKeyMsg := fixtureDHKeyMsg(otrV3{})
	_, _, err := authStateAwaitingDHKey{}.receiveDHKeyMessage(&c, sameDHKeyMsg)

	assertEquals(t, err, errShortRandomRead)
}

func Test_authStateAwaitingSig_receiveDHKeyMessage_returnsErrorIfprocessDHKeyReturnsError(t *testing.T) {
	ourDHCommitAKE := fixtureAKE()
	ourDHCommitAKE.dhCommitMessage()

	c := newAkeContext(otrV3{}, fixtureRand())
	c.x = ourDHCommitAKE.x
	c.gx = ourDHCommitAKE.gx
	c.ourKey = bobPrivateKey

	_, _, err := authStateAwaitingSig{}.receiveDHKeyMessage(&c, []byte{0x01, 0x02})

	assertEquals(t, err, errInvalidOTRMessage)
}

func Test_generateCommitMsgInstanceTags_returnsErrorIfMsgDoesntHaveMsgHeader(t *testing.T) {
	ake := fixtureAKE()
	err := generateCommitMsgInstanceTags(&ake, []byte{0x00, 0x01})
	assertEquals(t, err, errInvalidOTRMessage)
}

func Test_generateCommitMsgInstanceTags_returnsErrorIfMsgIsntLongEnoughForInstanceTag(t *testing.T) {
	ake := fixtureAKE()
	err := generateCommitMsgInstanceTags(&ake, []byte{0x00, 0x01, 0x02, 0x00, 0x00, 0x00})
	assertEquals(t, err, errInvalidOTRMessage)
}

func Test_authStateAwaitingRevealSig_receiveDHCommitMessage_returnsErrorIfProcessDHCommitOrGenerateCommitInstanceTagsFailsFails(t *testing.T) {
	ourDHCommitAKE := fixtureAKE()
	ourDHCommitAKE.dhCommitMessage()

	c := newAkeContext(otrV3{}, fixtureRand())
	c.gx = ourDHCommitAKE.gx

	_, _, err := authStateAwaitingRevealSig{}.receiveDHCommitMessage(&c, []byte{0x00, 0x00})
	assertEquals(t, err, errInvalidOTRMessage)
}

func Test_authStateNone_receiveDHCommitMessage_returnsErrorIfgenerateCommitMsgInstanceTagsFails(t *testing.T) {
	ourDHCommitAKE := fixtureAKE()
	ourDHCommitAKE.dhCommitMessage()

	c := newAkeContext(otrV3{}, fixtureRand())
	c.gx = ourDHCommitAKE.gx

	_, _, err := authStateNone{}.receiveDHCommitMessage(&c, []byte{0x00, 0x00})
	assertEquals(t, err, errInvalidOTRMessage)
}

func Test_authStateNone_receiveDHCommitMessage_returnsErrorIfdhKeyMessageFails(t *testing.T) {
	ourDHCommitAKE := fixtureAKE()
	ourDHCommitAKE.dhCommitMessage()

	c := newAkeContext(otrV2{}, fixedRand([]string{"ABCD"}))
	c.gx = ourDHCommitAKE.gx

	_, _, err := authStateNone{}.receiveDHCommitMessage(&c, []byte{0x00, 0x00})
	assertEquals(t, err, errShortRandomRead)
}

func Test_authStateNone_receiveDHCommitMessage_returnsErrorIfPcoessDHCommitFails(t *testing.T) {
	ourDHCommitAKE := fixtureAKE()
	ourDHCommitAKE.dhCommitMessage()

	c := newAkeContext(otrV2{}, fixtureRand())
	c.gx = ourDHCommitAKE.gx

	_, _, err := authStateNone{}.receiveDHCommitMessage(&c, []byte{0x00, 0x00})
	assertEquals(t, err, errInvalidOTRMessage)
}

func Test_authStateNone_receiveQueryMessage_returnsNoErrorForValidMessage(t *testing.T) {
	c := newAkeContext(otrV3{}, fixtureRand())
	c.addPolicy(allowV3)
	_, _, err := authStateNone{}.receiveQueryMessage(&c, []byte("?OTRv3?"))
	assertEquals(t, err, nil)
}

func Test_authStateNone_receiveQueryMessage_returnsErrorIfNoCompatibleVersionCouldBeFound(t *testing.T) {
	c := newAkeContext(otrV3{}, fixtureRand())
	c.addPolicy(allowV3)
	_, _, err := authStateNone{}.receiveQueryMessage(&c, []byte("?OTRv2?"))
	assertEquals(t, err, errInvalidVersion)
}

func Test_authStateNone_receiveQueryMessage_returnsErrorIfDhCommitMessageGeneratesError(t *testing.T) {
	c := newAkeContext(otrV2{}, fixedRand([]string{"ABCDABCD"}))
	c.addPolicy(allowV2)
	_, _, err := authStateNone{}.receiveQueryMessage(&c, []byte("?OTRv2?"))
	assertEquals(t, err, errShortRandomRead)
}

func Test_authStateAwaitingDHKey_receiveDHCommitMessage_failsIfMsgDoesntHaveHeader(t *testing.T) {
	ourDHCommitAKE := fixtureAKE()
	ourDHCommitAKE.dhCommitMessage()

	c := newAkeContext(otrV2{}, fixtureRand())
	c.gx = ourDHCommitAKE.gx

	_, _, err := authStateAwaitingDHKey{}.receiveDHCommitMessage(&c, []byte{0x00, 0x00})
	assertEquals(t, err, errInvalidOTRMessage)
}

func Test_authStateAwaitingDHKey_receiveDHCommitMessage_failsIfCantExtractFirstPart(t *testing.T) {
	ourDHCommitAKE := fixtureAKE()
	ourDHCommitAKE.dhCommitMessage()

	c := newAkeContext(otrV2{}, fixtureRand())
	c.gx = ourDHCommitAKE.gx

	_, _, err := authStateAwaitingDHKey{}.receiveDHCommitMessage(&c, []byte{0x00, 0x00, 0x00, 0x01})
	assertEquals(t, err, errInvalidOTRMessage)
}

func Test_authStateAwaitingDHKey_receiveDHCommitMessage_failsIfCantExtractSecondPart(t *testing.T) {
	ourDHCommitAKE := fixtureAKE()
	ourDHCommitAKE.dhCommitMessage()

	c := newAkeContext(otrV2{}, fixtureRand())
	c.gx = ourDHCommitAKE.gx

	_, _, err := authStateAwaitingDHKey{}.receiveDHCommitMessage(&c, []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x01, 0x00, 0x01, 0x02})
	assertEquals(t, err, errInvalidOTRMessage)
}
