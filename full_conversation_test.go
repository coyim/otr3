package otr3

import (
	"crypto/rand"
	"testing"
)

func Test_conversation_SMPStateMachineStartsAtSmpExpect1(t *testing.T) {
	c := newConversation(otrV3{}, fixtureRand())
	assertEquals(t, c.smp.state, smpStateExpect1{})
}

func Test_receive_generatesErrorIfDoesNotHaveASecureChannel(t *testing.T) {
	states := []msgState{
		plainText, finished,
	}
	c := bobContextAfterAKE()
	c.msgState = encrypted
	smpMsg := fixtureMessage1()
	dataMsg, _ := c.genDataMsg(nil, smpMsg.tlv())
	m := dataMsg.serialize()
	m, _ = c.wrapMessageHeader(msgTypeData, m)
	for _, s := range states {
		c.msgState = s
		_, _, err := c.receiveDecoded(m)
		assertEquals(t, err, errEncryptedMessageWithNoSecureChannel)
	}
}

func Test_receive_doesntGenerateErrorIfThereIsNoSecureChannelButTheMessageIsIGNORE_UNREADABLE(t *testing.T) {
	states := []msgState{
		plainText, finished,
	}
	c := bobContextAfterAKE()
	c.msgState = encrypted
	smpMsg := fixtureMessage1()
	dataMsg, _ := c.genDataMsgWithFlag(nil, messageFlagIgnoreUnreadable, smpMsg.tlv())
	m, _ := c.wrapMessageHeader(msgTypeData, dataMsg.serialize())

	for _, s := range states {
		c.msgState = s
		_, _, err := c.receiveDecoded(m)
		assertNil(t, err)
	}
}

func Test_AKE_forVersion3And2InThePolicy(t *testing.T) {
	alice := &Conversation{Rand: rand.Reader}
	alice.OurKey = alicePrivateKey
	alice.Policies = policies(allowV2 | allowV3)
	alice.TheirKey = &bobPrivateKey.PublicKey

	bob := &Conversation{Rand: rand.Reader}
	bob.OurKey = bobPrivateKey
	bob.Policies = policies(allowV2 | allowV3)
	bob.TheirKey = &alicePrivateKey.PublicKey

	var toSend []ValidMessage
	var err error
	msg := alice.queryMessage()

	//Alice send Bob queryMsg
	_, toSend, err = bob.Receive(msg)
	assertEquals(t, err, nil)
	assertEquals(t, bob.ake.state, authStateAwaitingDHKey{})

	//Bob send Alice DHCommit
	_, toSend, err = alice.Receive(toSend[0])
	assertEquals(t, alice.ake.state, authStateAwaitingRevealSig{})
	assertEquals(t, err, nil)

	//Alice send Bob DHKey
	_, toSend, err = bob.Receive(toSend[0])
	m, _ := bob.decode(encodedMessage(toSend[0]))
	assertEquals(t, err, nil)
	assertDeepEquals(t, bob.ake.state, authStateAwaitingSig{revealSigMsg: m})

	//Bob send Alice RevealSig
	_, toSend, err = alice.Receive(toSend[0])
	assertEquals(t, err, nil)
	assertEquals(t, alice.ake.state, authStateNone{})

	//Alice send Bob Sig
	_, toSend, err = bob.Receive(toSend[0])
	assertEquals(t, err, nil)
	assertEquals(t, bob.ake.state, authStateNone{})

	// "When starting a private Conversation [...],
	// generate two DH key pairs for yourself, and set our_keyid = 2"
	assertEquals(t, alice.keys.ourKeyID, uint32(2))
	assertEquals(t, alice.keys.ourCurrentDHKeys.priv.BitLen() > 0, true)
	assertEquals(t, alice.keys.ourCurrentDHKeys.pub.BitLen() > 0, true)
	assertEquals(t, alice.keys.ourPreviousDHKeys.priv.BitLen() > 0, true)
	assertEquals(t, alice.keys.ourPreviousDHKeys.pub.BitLen() > 0, true)

	assertEquals(t, bob.keys.ourKeyID, uint32(2))
	assertEquals(t, bob.keys.ourCurrentDHKeys.priv.BitLen() > 0, true)
	assertEquals(t, bob.keys.ourCurrentDHKeys.pub.BitLen() > 0, true)
	assertEquals(t, bob.keys.ourPreviousDHKeys.priv.BitLen() > 0, true)
	assertEquals(t, bob.keys.ourPreviousDHKeys.pub.BitLen() > 0, true)
}

func Test_AKE_withVersion3ButWithoutVersion2InThePolicy(t *testing.T) {
	alice := &Conversation{Rand: rand.Reader}
	alice.OurKey = alicePrivateKey
	alice.Policies = policies(allowV3)
	alice.TheirKey = &bobPrivateKey.PublicKey

	bob := &Conversation{Rand: rand.Reader}
	bob.OurKey = bobPrivateKey
	bob.Policies = policies(allowV3)
	bob.TheirKey = &alicePrivateKey.PublicKey

	var toSend []ValidMessage
	var err error
	msg := alice.queryMessage()

	//Alice send Bob queryMsg
	_, toSend, err = bob.Receive(msg)
	assertEquals(t, err, nil)
	assertEquals(t, bob.ake.state, authStateAwaitingDHKey{})

	//Bob send Alice DHCommit
	_, toSend, err = alice.Receive(toSend[0])
	assertEquals(t, alice.ake.state, authStateAwaitingRevealSig{})
	assertEquals(t, err, nil)

	//Alice send Bob DHKey
	_, toSend, err = bob.Receive(toSend[0])
	m, _ := bob.decode(encodedMessage(toSend[0]))
	assertEquals(t, err, nil)
	assertDeepEquals(t, bob.ake.state, authStateAwaitingSig{revealSigMsg: m})

	//Bob send Alice RevealSig
	_, toSend, err = alice.Receive(toSend[0])
	assertEquals(t, err, nil)
	assertEquals(t, alice.ake.state, authStateNone{})

	//Alice send Bob Sig
	_, toSend, err = bob.Receive(toSend[0])
	assertEquals(t, err, nil)
	assertEquals(t, bob.ake.state, authStateNone{})

	// "When starting a private Conversation [...],
	// generate two DH key pairs for yourself, and set our_keyid = 2"
	assertEquals(t, alice.keys.ourKeyID, uint32(2))
	assertEquals(t, alice.keys.ourCurrentDHKeys.priv.BitLen() > 0, true)
	assertEquals(t, alice.keys.ourCurrentDHKeys.pub.BitLen() > 0, true)
	assertEquals(t, alice.keys.ourPreviousDHKeys.priv.BitLen() > 0, true)
	assertEquals(t, alice.keys.ourPreviousDHKeys.pub.BitLen() > 0, true)

	assertEquals(t, bob.keys.ourKeyID, uint32(2))
	assertEquals(t, bob.keys.ourCurrentDHKeys.priv.BitLen() > 0, true)
	assertEquals(t, bob.keys.ourCurrentDHKeys.pub.BitLen() > 0, true)
	assertEquals(t, bob.keys.ourPreviousDHKeys.priv.BitLen() > 0, true)
	assertEquals(t, bob.keys.ourPreviousDHKeys.pub.BitLen() > 0, true)
}

func Test_processDataMessageShouldExtractData(t *testing.T) {
	var toSend []ValidMessage
	var err error

	alice := &Conversation{Rand: rand.Reader}
	alice.Policies = policies(allowV2 | allowV3)
	alice.OurKey = alicePrivateKey

	bob := &Conversation{Rand: rand.Reader}
	bob.Policies = policies(allowV2 | allowV3)
	bob.OurKey = bobPrivateKey

	msg := []byte("?OTRv3?")

	//Alice send Bob queryMsg
	_, toSend, err = bob.Receive(msg)
	assertNil(t, err)
	assertEquals(t, bob.ake.state, authStateAwaitingDHKey{})
	assertEquals(t, bob.version, otrV3{})

	//Bob send Alice DHCommit
	_, toSend, err = alice.Receive(toSend[0])
	assertEquals(t, alice.ake.state, authStateAwaitingRevealSig{})
	assertNil(t, err)

	//Alice send Bob DHKey
	_, toSend, err = bob.Receive(toSend[0])
	m, _ := bob.decode(encodedMessage(toSend[0]))
	assertNil(t, err)
	assertDeepEquals(t, bob.ake.state, authStateAwaitingSig{revealSigMsg: m})

	//Bob send Alice RevealSig
	_, toSend, err = alice.Receive(toSend[0])
	assertNil(t, err)
	assertEquals(t, alice.ake.state, authStateNone{})

	//Alice send Bob Sig
	_, toSend, err = bob.Receive(toSend[0])
	assertNil(t, err)
	assertEquals(t, bob.ake.state, authStateNone{})

	// Alice sends a message to bob
	msg = []byte("hello")
	dataMsg, _ := alice.genDataMsg(msg)
	m, _ = alice.wrapMessageHeader(msgTypeData, dataMsg.serialize())

	bob.updateLastSent()
	plain, ret, err := bob.receiveDecoded(m)

	assertDeepEquals(t, err, nil)
	assertDeepEquals(t, plain, MessagePlaintext(msg))
	assertNil(t, ret)
}
