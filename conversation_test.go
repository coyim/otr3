package otr3

import (
	"crypto/rand"
	"testing"
)

func Test_contextSMPStateMachineStartsAtSmpExpect1(t *testing.T) {
	c := newConversation(otrV3{}, fixtureRand())
	assertEquals(t, c.smpState, smpStateExpect1{})
}

func Test_AKE_process(t *testing.T) {
	alice := newConversation(otrV3{}, rand.Reader)
	bob := newConversation(otrV3{}, rand.Reader)
	alice.addPolicy(allowV2)
	bob.addPolicy(allowV2)
	alice.addPolicy(allowV3)
	bob.addPolicy(allowV3)
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
	assertEquals(t, bob.authState, authStateAwaitingSig{})

	//Bob send Alice RevealSig
	toSend, err = alice.receive(toSend)
	assertEquals(t, err, nil)
	assertEquals(t, alice.authState, authStateNone{})

	//Bob send Alice Sig
	toSend, err = bob.receive(toSend)
	assertEquals(t, err, nil)
	assertEquals(t, bob.authState, authStateNone{})
}
