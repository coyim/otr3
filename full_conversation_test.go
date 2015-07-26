package otr3

import (
	"crypto/rand"
	"testing"
)

func Test_conversation_SMPStateMachineStartsAtSmpExpect1(t *testing.T) {
	c := newConversation(otrV3{}, fixtureRand())
	assertEquals(t, c.smpState, smpStateExpect1{})
}

func Test_receive_AbortsSMPStateMachineIfDoesNotHaveASecureChannel(t *testing.T) {
	states := []msgState{
		plainText, finished,
	}

	c := bobContextAfterAKE()

	smpMsg := fixtureMessage1()
	m := c.genDataMsg(nil, smpMsg.tlv()).serialize()
	smpAbortMsg := smpMessageAbort{}.tlv().serialize()

	for _, s := range states {
		c.msgState = s

		toSend, err := c.receive(m)
		assertEquals(t, err, errEncryptedMessageWithNoSecureChannel)
		assertEquals(t, c.smpState, smpStateExpect1{})
		assertDeepEquals(t, toSend, smpAbortMsg)
	}
}

func Test_AKEHappyPath(t *testing.T) {
	alice := newConversation(otrV3{}, rand.Reader)
	bob := newConversation(otrV3{}, rand.Reader)
	alice.policies.add(allowV2)
	bob.policies.add(allowV2)
	alice.policies.add(allowV3)
	bob.policies.add(allowV3)
	alice.ourKey = alicePrivateKey
	bob.ourKey = bobPrivateKey
	alice.theirKey = &bobPrivateKey.PublicKey
	bob.theirKey = &alicePrivateKey.PublicKey

	msg := []byte("?OTRv3?")
	var toSend []byte
	var err error
	//Alice send Bob queryMsg
	toSend, err = bob.receive(msg)
	assertEquals(t, err, nil)
	assertEquals(t, bob.authState, authStateAwaitingDHKey{})

	//Bob send Alice DHCommit
	toSend, err = alice.receive(toSend)
	assertEquals(t, alice.authState, authStateAwaitingRevealSig{})
	assertEquals(t, err, nil)

	//Alice send Bob DHKey
	toSend, err = bob.receive(toSend)
	assertEquals(t, err, nil)
	assertDeepEquals(t, bob.authState, authStateAwaitingSig{revealSigMsg: toSend})

	//Bob send Alice RevealSig
	toSend, err = alice.receive(toSend)
	assertEquals(t, err, nil)
	assertEquals(t, alice.authState, authStateNone{})

	//Alice send Bob Sig
	toSend, err = bob.receive(toSend)
	assertEquals(t, err, nil)
	assertEquals(t, bob.authState, authStateNone{})
}

func Test_AKENotAllowV2(t *testing.T) {
	alice := newConversation(otrV3{}, rand.Reader)
	bob := newConversation(otrV3{}, rand.Reader)
	alice.policies.add(allowV3)
	bob.policies.add(allowV3)
	alice.ourKey = alicePrivateKey
	bob.ourKey = bobPrivateKey
	alice.theirKey = &bobPrivateKey.PublicKey
	bob.theirKey = &alicePrivateKey.PublicKey

	msg := []byte("?OTRv3?")
	var toSend []byte
	var nilB []byte
	var err error
	//Alice send Bob queryMsg
	toSend, err = bob.receive(msg)
	assertEquals(t, err, nil)
	assertEquals(t, bob.authState, authStateAwaitingDHKey{})

	//Bob send Alice DHCommit
	toSend, err = alice.receive(toSend)
	assertEquals(t, alice.authState, authStateAwaitingRevealSig{})
	assertEquals(t, err, nil)

	//Alice send Bob DHKey
	toSend, err = bob.receive(toSend)
	assertEquals(t, err, nil)
	assertDeepEquals(t, bob.authState, authStateAwaitingSig{revealSigMsg: toSend})

	//Bob send Alice RevealSig
	toSend, err = alice.receive(toSend)
	assertEquals(t, err, nil)
	assertEquals(t, alice.authState, authStateAwaitingRevealSig{})
	assertDeepEquals(t, toSend, nilB)
}

func Test_processDataMessageShouldExtractData(t *testing.T) {
	alice := newConversation(otrV3{}, rand.Reader)
	bob := newConversation(otrV3{}, rand.Reader)
	alice.policies.add(allowV2)
	bob.policies.add(allowV2)
	alice.policies.add(allowV3)
	bob.policies.add(allowV3)
	alice.ourKey = alicePrivateKey
	bob.ourKey = bobPrivateKey
	alice.theirKey = &bobPrivateKey.PublicKey
	bob.theirKey = &alicePrivateKey.PublicKey

	msg := []byte("?OTRv3?")
	var toSend []byte
	var err error
	//Alice send Bob queryMsg
	toSend, err = bob.receive(msg)
	assertEquals(t, err, nil)
	assertEquals(t, bob.authState, authStateAwaitingDHKey{})

	//Bob send Alice DHCommit
	toSend, err = alice.receive(toSend)
	assertEquals(t, alice.authState, authStateAwaitingRevealSig{})
	assertEquals(t, err, nil)

	//Alice send Bob DHKey
	toSend, err = bob.receive(toSend)
	assertEquals(t, err, nil)
	assertDeepEquals(t, bob.authState, authStateAwaitingSig{revealSigMsg: toSend})

	//Bob send Alice RevealSig
	toSend, err = alice.receive(toSend)
	assertEquals(t, err, nil)
	assertEquals(t, alice.authState, authStateNone{})

	//Alice send Bob Sig
	toSend, err = bob.receive(toSend)
	assertEquals(t, err, nil)
	assertEquals(t, bob.authState, authStateNone{})

	datamsg := alice.genDataMsg([]byte("hello")).serialize()
	bob.processDataMessage(datamsg)

	//FIXME: assertDeepEquals(t, out, []byte("hello"))
}
