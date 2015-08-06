package otr3

import (
	"crypto/rand"
	"testing"
	"time"
)

func fixtureCorrectResend(c *Conversation) {
	c.resend.lastMessage = MessagePlaintext("hello")
	c.resend.mayRetransmit = retransmitExact
	c.updateLastSent()
}

func Test_shouldRetransmit_returnsFalseIfThereIsNoLastMessage(t *testing.T) {
	c := &Conversation{}
	fixtureCorrectResend(c)
	c.resend.lastMessage = nil

	assertEquals(t, c.shouldRetransmit(), false)
}

func Test_shouldRetransmit_returnTrueIfAllTheConditionsForResendingAreMet(t *testing.T) {
	c := &Conversation{}
	fixtureCorrectResend(c)

	assertEquals(t, c.shouldRetransmit(), true)
}

func Test_shouldRetransmit_returnFalseIfTheLastMessageWasSentTooFarBackInTime(t *testing.T) {
	c := &Conversation{}
	fixtureCorrectResend(c)
	c.heartbeat.lastSent = time.Now().Add(-61 * time.Second)

	assertEquals(t, c.shouldRetransmit(), false)
}

func Test_shouldRetransmit_returnTrueWhenFlagIsRetransmitWithPrefix(t *testing.T) {
	c := &Conversation{}
	fixtureCorrectResend(c)
	c.resend.mayRetransmit = retransmitWithPrefix

	assertEquals(t, c.shouldRetransmit(), true)
}

func Test_shouldRetransmit_returnFalseWhenFlagIsNoRetransmit(t *testing.T) {
	c := &Conversation{}
	fixtureCorrectResend(c)
	c.resend.mayRetransmit = noRetransmit

	assertEquals(t, c.shouldRetransmit(), false)
}

func Test_maybeRetransmit_returnsNothingWhenShouldntRetransmit(t *testing.T) {
	c := &Conversation{}
	fixtureCorrectResend(c)
	c.resend.lastMessage = nil

	res := c.maybeRetransmit()

	assertNil(t, res)
}

func Test_maybeRetransmit_createsADataMessageWithTheExactMessageWhenAskedToRetransmitExact(t *testing.T) {
	c := newConversation(otrV3{}, rand.Reader)
	c.Policies.add(allowV3)
	c.OurKey = bobPrivateKey
	c.smp.secret = bnFromHex("ABCDE56321F9A9F8E364607C8C82DECD8E8E6209E2CB952C7E649620F5286FE3")

	plain := plainDataMsg{
		message: []byte(""),
	}

	_, c.keys = fixtureDataMsg(plain)

	c.msgState = encrypted

	fixtureCorrectResend(c)
	c.resend.lastMessage = MessagePlaintext("Something else to think about")

	res := c.maybeRetransmit()
	dec := fixtureDecryptDataMsg(res)

	assertDeepEquals(t, MessagePlaintext(dec.message), MessagePlaintext("Something else to think about"))
	assertEquals(t, len(dec.tlvs), 1)
	assertEquals(t, dec.tlvs[0].tlvType, tlvTypePadding)
}

func Test_maybeRetransmit_createsADataMessageWithTheResendPrefixAndMessageWhenAskedToRetransmitWithPrefix(t *testing.T) {
	c := newConversation(otrV3{}, rand.Reader)
	c.Policies.add(allowV3)
	c.OurKey = bobPrivateKey
	c.smp.secret = bnFromHex("ABCDE56321F9A9F8E364607C8C82DECD8E8E6209E2CB952C7E649620F5286FE3")

	plain := plainDataMsg{
		message: []byte(""),
	}

	_, c.keys = fixtureDataMsg(plain)

	c.msgState = encrypted

	fixtureCorrectResend(c)
	c.resend.mayRetransmit = retransmitWithPrefix
	c.resend.lastMessage = MessagePlaintext("Something else to think about")

	res := c.maybeRetransmit()
	dec := fixtureDecryptDataMsg(res)

	assertDeepEquals(t, MessagePlaintext(dec.message), MessagePlaintext("[resent] Something else to think about"))
	assertEquals(t, len(dec.tlvs), 1)
	assertEquals(t, dec.tlvs[0].tlvType, tlvTypePadding)
}

func Test_maybeRetransmit_createsADataMessageWithTheCustomResendPrefixAndMessageWhenAskedToRetransmitWithPrefix(t *testing.T) {
	c := newConversation(otrV3{}, rand.Reader)
	c.Policies.add(allowV3)
	c.OurKey = bobPrivateKey
	c.smp.secret = bnFromHex("ABCDE56321F9A9F8E364607C8C82DECD8E8E6209E2CB952C7E649620F5286FE3")

	plain := plainDataMsg{
		message: []byte(""),
	}

	_, c.keys = fixtureDataMsg(plain)

	c.msgState = encrypted

	fixtureCorrectResend(c)
	c.resend.mayRetransmit = retransmitWithPrefix
	c.resend.lastMessage = MessagePlaintext("Something much more to think about")
	c.resend.messageTransform = func(msg []byte) []byte {
		return append(append([]byte("<resend>"), msg...), []byte("</resend>")...)
	}

	res := c.maybeRetransmit()
	dec := fixtureDecryptDataMsg(res)

	assertDeepEquals(t, MessagePlaintext(dec.message), MessagePlaintext("<resend>Something much more to think about</resend>"))
	assertEquals(t, len(dec.tlvs), 1)
	assertEquals(t, dec.tlvs[0].tlvType, tlvTypePadding)
}

func Test_maybeRetransmit_updatesLastSentWhenSendingAMessage(t *testing.T) {
	c := newConversation(otrV3{}, rand.Reader)
	c.Policies.add(allowV3)
	c.OurKey = bobPrivateKey
	c.smp.secret = bnFromHex("ABCDE56321F9A9F8E364607C8C82DECD8E8E6209E2CB952C7E649620F5286FE3")

	plain := plainDataMsg{
		message: []byte(""),
	}

	_, c.keys = fixtureDataMsg(plain)

	c.msgState = encrypted

	fixtureCorrectResend(c)

	setSent := time.Now().Add(-30 * time.Second)
	c.heartbeat.lastSent = setSent

	c.maybeRetransmit()

	assertNotEquals(t, c.heartbeat.lastSent, setSent)
}
