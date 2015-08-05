package otr3

import (
	"crypto/rand"
	"testing"
)

func Test_receiveDecoded_resolveProtocolVersion(t *testing.T) {
	c := &Conversation{}
	c.Policies = policies(allowV3)
	_, _, err := c.receiveDecoded(fixtureDHCommitMsg())

	assertNil(t, err)
	assertEquals(t, c.version, otrV3{})

	c = &Conversation{}
	c.Policies = policies(allowV2)
	_, _, err = c.receiveDecoded(fixtureDHCommitMsgV2())

	assertNil(t, err)
	assertEquals(t, c.version, otrV2{})
}

func Test_receiveDecoded_checkMessageVersion(t *testing.T) {
	cV2 := &Conversation{version: otrV2{}}
	msgV2, _ := cV2.wrapMessageHeader(msgTypeDHCommit, nil)

	cV3 := &Conversation{version: otrV3{}}
	msgV3, _ := cV3.wrapMessageHeader(msgTypeDHCommit, nil)

	_, _, err := cV2.receiveDecoded(msgV3)
	assertEquals(t, err, errWrongProtocolVersion)

	_, _, err = cV3.receiveDecoded(msgV2)
	assertEquals(t, err, errWrongProtocolVersion)
}

func Test_receiveDecoded_returnsErrorIfTheMessageIsCorrupt(t *testing.T) {
	cV3 := &Conversation{version: otrV3{}}
	cV3.ourInstanceTag = 0x101
	cV3.theirInstanceTag = 0x102

	_, _, err := cV3.receiveDecoded([]byte{})
	assertEquals(t, err, errInvalidOTRMessage)

	_, _, err = cV3.receiveDecoded([]byte{0x00, 0x00})
	assertEquals(t, err, errWrongProtocolVersion)

	_, _, err = cV3.receiveDecoded([]byte{0x00, 0x03, 0x56, 0x00, 0x00, 0x01, 0x02, 0x00, 0x00, 0x01, 0x01})
	assertDeepEquals(t, err, newOtrError("unknown message type 0x56"))
}

func Test_receivePlaintext_signalsAMessageEventThatItWasUnencryptedIfNotInPlaintextMessageMode(t *testing.T) {
	c := &Conversation{}
	c.msgState = encrypted

	c.expectMessageEvent(t, func() {
		c.receivePlaintext(ValidMessage("Hello world"))
	}, MessageEventReceivedMessageUnencrypted, []byte("Hello world"), nil)
}

func Test_receivePlaintext_signalsAMessageEventThatItWasUnencryptedIfRequiringEncryption(t *testing.T) {
	c := &Conversation{}
	c.msgState = plainText
	c.Policies = policies(requireEncryption)

	c.expectMessageEvent(t, func() {
		c.receivePlaintext(ValidMessage("Hello world"))
	}, MessageEventReceivedMessageUnencrypted, []byte("Hello world"), nil)
}

func Test_receivePlaintext_doesntSignalAMessageEventThatItWasUnencryptedIfNotInPlaintextMessageModeIfNotRequiringEncryption(t *testing.T) {
	c := &Conversation{}
	c.msgState = plainText

	c.doesntExpectMessageEvent(t, func() {
		c.receivePlaintext(ValidMessage("Hello world"))
	})
}

func Test_receiveTaggedPlaintext_signalsAMessageEventThatItWasUnencryptedIfNotInPlaintextMessageMode(t *testing.T) {
	c := &Conversation{}
	c.msgState = encrypted

	c.expectMessageEvent(t, func() {
		c.receiveTaggedPlaintext(ValidMessage("Hello \t  \t\t\t\t \t \t \t   world"))
	}, MessageEventReceivedMessageUnencrypted, []byte("Hello world"), nil)
}

func Test_receiveTaggedPlaintext_signalsAMessageEventThatItWasUnencryptedIfRequiringEncryption(t *testing.T) {
	c := &Conversation{}
	c.msgState = plainText
	c.Policies = policies(requireEncryption)

	c.expectMessageEvent(t, func() {
		c.receiveTaggedPlaintext(ValidMessage("Hello \t  \t\t\t\t \t \t \t   world"))
	}, MessageEventReceivedMessageUnencrypted, []byte("Hello world"), nil)
}

func Test_receiveTaggedPlaintext_doesntSignalAMessageEventThatItWasUnencryptedIfNotInPlaintextMessageModeIfNotRequiringEncryption(t *testing.T) {
	c := &Conversation{}
	c.msgState = plainText

	c.doesntExpectMessageEvent(t, func() {
		c.receiveTaggedPlaintext(ValidMessage("Hello \t  \t\t\t\t \t \t \t   world"))
	})
}

func Test_Receive_signalsAMessageEventWhenWeReceiveAMessageThatLooksLikeAnOTRMessageButWeCantUnderstandIt(t *testing.T) {
	c := &Conversation{}
	c.Policies = policies(allowV3)

	c.expectMessageEvent(t, func() {
		c.Receive(ValidMessage("?OTR Something: strange"))
	}, MessageEventReceivedMessageUnrecognized, nil, nil)
}

func Test_Recieve_signalsAMessageEventWhenWeReceiveADataMessageForAnotherInstance(t *testing.T) {
	alice := &Conversation{Rand: rand.Reader}
	alice.ourInstanceTag = 0x201
	alice.theirInstanceTag = 0x301
	alice.OurKey = alicePrivateKey
	alice.Policies = policies(allowV3)
	alice.TheirKey = &bobPrivateKey.PublicKey

	bob := &Conversation{Rand: rand.Reader}
	bob.ourInstanceTag = 0x301
	bob.theirInstanceTag = 0x201
	bob.OurKey = bobPrivateKey
	bob.Policies = policies(allowV3)
	bob.TheirKey = &alicePrivateKey.PublicKey

	var toSend []ValidMessage
	msg := alice.queryMessage()
	_, toSend, _ = bob.Receive(msg)
	encoded := toSend[0][5 : len(toSend[0])-1]
	decoded, _ := b64decode(encoded)
	decoded[6] = 0x02 // Change the instance tag low byte
	reencoded := append(append(msgMarker, b64encode(decoded)...), '.')

	alice.expectMessageEvent(t, func() {
		alice.Receive(reencoded)
	}, MessageEventReceivedMessageForOtherInstance, nil, nil)

	decoded[6] = 0x01
	decoded[10] = 0x05
	reencoded = append(append(msgMarker, b64encode(decoded)...), '.')

	alice.expectMessageEvent(t, func() {
		alice.Receive(reencoded)
	}, MessageEventReceivedMessageForOtherInstance, nil, nil)
}

func Test_Receive_NoFragments(t *testing.T) {
	alice := aliceContextAfterAKE()
	alice.msgState = encrypted
	alice.keys.ourCounter = 1
	bob := bobContextAfterAKE()
	bob.msgState = encrypted
	fragments, _ := alice.createSerializedDataMessage(MessagePlaintext("hello!"), messageFlagNormal, []tlv{})
	plain, _, err := bob.Receive(fragments[0])
	assertNil(t, err)
	assertDeepEquals(t, plain, MessagePlaintext("hello!"))
}

func Test_Receive_Fragments(t *testing.T) {
	alice := aliceContextAfterAKE()
	alice.msgState = encrypted
	alice.keys.ourCounter = 1
	alice.setFragmentSize(200)

	bob := bobContextAfterAKE()
	bob.msgState = encrypted
	fragments, _ := alice.createSerializedDataMessage(MessagePlaintext("hello!"), messageFlagNormal, []tlv{})
	plain, _, err := bob.Receive(fragments[0])
	assertNil(t, err)
	plain, _, err = bob.Receive(fragments[1])
	assertNil(t, err)
	plain, _, err = bob.Receive(fragments[2])
	assertNil(t, err)
	plain, _, err = bob.Receive(fragments[3])
	assertNil(t, err)
	assertDeepEquals(t, plain, MessagePlaintext("hello!"))
}
