package otr3

import (
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
	c.keys.ourCounter = 1
	c.keys.theirCounter = 2
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
