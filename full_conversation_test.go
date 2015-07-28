package otr3

import (
	"crypto/rand"
	"testing"
)

func Test_conversation_SMPStateMachineStartsAtSmpExpect1(t *testing.T) {
	c := newConversation(otrV3{}, fixtureRand())
	assertEquals(t, c.smp.state, smpStateExpect1{})
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
		assertEquals(t, c.smp.state, smpStateExpect1{})
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
	assertEquals(t, bob.ake.state, authStateAwaitingDHKey{})

	//Bob send Alice DHCommit
	toSend, err = alice.receive(toSend)
	assertEquals(t, alice.ake.state, authStateAwaitingRevealSig{})
	assertEquals(t, err, nil)

	//Alice send Bob DHKey
	toSend, err = bob.receive(toSend)
	assertEquals(t, err, nil)
	assertDeepEquals(t, bob.ake.state, authStateAwaitingSig{revealSigMsg: toSend})

	//Bob send Alice RevealSig
	toSend, err = alice.receive(toSend)
	assertEquals(t, err, nil)
	assertEquals(t, alice.ake.state, authStateNone{})

	//Alice send Bob Sig
	toSend, err = bob.receive(toSend)
	assertEquals(t, err, nil)
	assertEquals(t, bob.ake.state, authStateNone{})

	// "When starting a private Conversation [...],
	// generate two DH key pairs for yourself, and set our_keyid = 2"
	assertEquals(t, alice.keys.ourKeyID, uint32(2))
	assertEquals(t, len(alice.keys.ourCurrentDHKeys.priv.Bytes()), 40)
	assertEquals(t, len(alice.keys.ourCurrentDHKeys.pub.Bytes()), 192)
	assertEquals(t, len(alice.keys.ourPreviousDHKeys.priv.Bytes()), 40)
	assertEquals(t, len(alice.keys.ourPreviousDHKeys.pub.Bytes()), 192)

	assertEquals(t, bob.keys.ourKeyID, uint32(2))
	assertEquals(t, len(bob.keys.ourCurrentDHKeys.priv.Bytes()), 40)
	assertEquals(t, len(bob.keys.ourCurrentDHKeys.pub.Bytes()), 192)
	assertEquals(t, len(bob.keys.ourPreviousDHKeys.priv.Bytes()), 40)
	assertEquals(t, len(bob.keys.ourPreviousDHKeys.pub.Bytes()), 192)
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
	assertEquals(t, bob.ake.state, authStateAwaitingDHKey{})

	//Bob send Alice DHCommit
	toSend, err = alice.receive(toSend)
	assertEquals(t, alice.ake.state, authStateAwaitingRevealSig{})
	assertEquals(t, err, nil)

	//Alice send Bob DHKey
	toSend, err = bob.receive(toSend)
	assertEquals(t, err, nil)
	assertDeepEquals(t, bob.ake.state, authStateAwaitingSig{revealSigMsg: toSend})

	//Bob send Alice RevealSig
	toSend, err = alice.receive(toSend)
	assertEquals(t, err, nil)
	assertEquals(t, alice.ake.state, authStateAwaitingRevealSig{})
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
	assertEquals(t, bob.ake.state, authStateAwaitingDHKey{})

	//Bob send Alice DHCommit
	toSend, err = alice.receive(toSend)
	assertEquals(t, alice.ake.state, authStateAwaitingRevealSig{})
	assertEquals(t, err, nil)

	//Alice send Bob DHKey
	toSend, err = bob.receive(toSend)
	assertEquals(t, err, nil)
	assertDeepEquals(t, bob.ake.state, authStateAwaitingSig{revealSigMsg: toSend})

	//Bob send Alice RevealSig
	toSend, err = alice.receive(toSend)
	assertEquals(t, err, nil)
	assertEquals(t, alice.ake.state, authStateNone{})

	//Alice send Bob Sig
	toSend, err = bob.receive(toSend)
	assertEquals(t, err, nil)
	assertEquals(t, bob.ake.state, authStateNone{})
	datamsg := alice.genDataMsg([]byte("hello")).serialize()

	plain, tlvs, err := bob.processDataMessage(datamsg)

	assertDeepEquals(t, err, nil)
	assertDeepEquals(t, plain, []byte("hello"))
	padding := paddingGranularity - ((len(plain) + tlvHeaderLen + nulByteLen) % paddingGranularity)
	assertDeepEquals(t, tlvs, []tlv{tlv{tlvType: 0, tlvLength: uint16(padding), tlvValue: make([]byte, padding)}})
}
