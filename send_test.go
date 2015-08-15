package otr3

import (
	"bytes"
	"math/big"
	"testing"
)

func Test_sendDHCommit_resetsTheKeyManagementContext(t *testing.T) {
	c := newConversation(otrV3{}, fixtureRand())
	c.keys.ourKeyID = 2
	c.keys.theirKeyID = 3
	c.keys.ourCurrentDHKeys = dhKeyPair{
		priv: big.NewInt(1),
		pub:  big.NewInt(2),
	}
	c.keys.ourPreviousDHKeys = dhKeyPair{
		priv: big.NewInt(3),
		pub:  big.NewInt(4),
	}
	c.keys.theirCurrentDHPubKey = big.NewInt(5)
	c.keys.theirPreviousDHPubKey = big.NewInt(6)
	c.keys.macKeyHistory.addKeys(2, 3, macKey{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 2, 3, 4})

	k1 := macKey{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 5, 6, 7, 8}
	k2 := macKey{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 8, 7, 6, 5}
	c.keys.oldMACKeys = []macKey{k1, k2}

	expectedKeyContext := keyManagementContext{
		oldMACKeys: []macKey{k1, k2},
	}
	_, err := c.sendDHCommit()
	assertEquals(t, err, nil)
	assertDeepEquals(t, c.keys, expectedKeyContext)
}

func Test_Send_signalsMessageEventIfTryingToSendWithoutEncryptedChannel(t *testing.T) {
	m := []byte("hello")
	c := bobContextAfterAKE()
	c.msgState = plainText
	c.Policies = policies(allowV3 | requireEncryption)

	c.expectMessageEvent(t, func() {
		c.Send(m)
	}, MessageEventEncryptionRequired, nil, nil)
}

func Test_Send_signalsMessageEventIfTryingToSendOnAFinishedChannel(t *testing.T) {
	m := []byte("hello")
	c := bobContextAfterAKE()
	c.msgState = finished
	c.Policies = policies(allowV3 | requireEncryption)

	c.expectMessageEvent(t, func() {
		c.Send(m)
	}, MessageEventConnectionEnded, nil, nil)
}

func Test_Send_signalsEncryptionErrorMessageEventIfSomethingWentWrong(t *testing.T) {
	msg := []byte("hello")

	c := bobContextAfterAKE()
	c.msgState = encrypted
	c.Policies = policies(allowV3)
	c.keys.theirKeyID = 0

	c.expectMessageEvent(t, func() {
		c.Send(msg)
	}, MessageEventEncryptionError, nil, nil)
}

func Test_Send_callsErrorMessageHandlerAndReturnsTheResultAsAnOTRErrorMessage(t *testing.T) {
	msg := []byte("hello")

	c := bobContextAfterAKE()
	c.msgState = encrypted
	c.Policies = policies(allowV3)
	c.keys.theirKeyID = 0

	c.errorMessageHandler = dynamicErrorMessageHandler{
		func(error ErrorCode) []byte {
			if error == ErrorCodeEncryptionError {
				return []byte("snowflake happened")
			}
			return []byte("nova happened")
		}}

	msgs, _ := c.Send(msg)
	assertDeepEquals(t, msgs[0], ValidMessage("?OTR Error: snowflake happened"))
}

func Test_Send_saveLastMessageWhenMsgIsPlainTextAndEncryptedIsExpected(t *testing.T) {
	m := []byte("hello")
	c := bobContextAfterAKE()
	c.msgState = plainText
	c.Policies = policies(allowV3 | requireEncryption)

	c.Send(m)

	assertDeepEquals(t, c.resend.lastMessage, MessagePlaintext(m))
}

func Test_Send_setsMayRetransmitFlagToExpectExactResending(t *testing.T) {
	m := []byte("hello")
	c := bobContextAfterAKE()
	c.msgState = plainText
	c.Policies = policies(allowV3 | requireEncryption)

	c.Send(m)

	assertEquals(t, c.resend.mayRetransmit, retransmitExact)
}

func captureStderr(f func()) string {
	originalStdErr := standardErrorOutput
	bt := bytes.NewBuffer(make([]byte, 0, 200))
	standardErrorOutput = bt

	f()

	defer func() {
		standardErrorOutput = originalStdErr
	}()

	return bt.String()
}

func Test_Send_printsDebugStatementToStderrIfGivenMagicString(t *testing.T) {
	m := []byte("hel?OTR!lo")
	c := bobContextAfterAKE()
	c.theirKey = &alicePrivateKey.PublicKey
	c.debug = true

	var ret []ValidMessage
	ss := captureStderr(func() {
		ret, _ = c.Send(m)
	})
	assertNil(t, ret)
	assertDeepEquals(t, ss, `Context:

  Our instance:   00000101
  Their instance: 00000101

  Msgstate: 0 (PLAINTEXT)

  Protocol version: 3
  OTR offer: NOT

  Auth info:
    State: 0 (NONE)
    Our keyid:   2
    Their keyid: 1
    Their fingerprint: 0BB01C360424522E94EE9C346CE877A1A4288B2F
    Proto version = 3

  SM state:
    Next expected: 0 (EXPECT1)
    Received_Q: 0
`)
}
