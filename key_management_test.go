package otr3

import (
	"errors"
	"math/big"
	"testing"
)

func Test_calculateDHSessionKeys(t *testing.T) {
	c := keyManagementContext{
		ourKeyID:   1,
		theirKeyID: 2,
		ourCurrentDHKeys: dhKeyPair{
			pub:  fixedgx,
			priv: fixedx,
		},
		theirPreviousDHPubKey: fixedgy,
	}

	sendingAESKey := bytesFromHex("42e258bebf031acf442f52d6ef52d6f1")
	sendingMACKey := bytesFromHex("a45e2b122f58bbe2042f73f092329ad9b5dfe23e")
	receivingAESKey := bytesFromHex("c778c71cb63161e8e06d245e77ff6430")
	receivingMACKey := bytesFromHex("03f8034b891b1e843db5bba9a41ec68a1f5f8bbf")

	keys, err := c.calculateDHSessionKeys(1, 1)

	assertEquals(t, err, nil)
	assertDeepEquals(t, keys.sendingAESKey[:], sendingAESKey)
	assertDeepEquals(t, keys.sendingMACKey[:], sendingMACKey)
	assertDeepEquals(t, keys.receivingAESKey[:], receivingAESKey)
	assertDeepEquals(t, keys.receivingMACKey[:], receivingMACKey)
}

func Test_calculateDHSessionKeys_storesGeneratedMACKeys(t *testing.T) {
	ourKeyID := uint32(1)
	theirKeyID := uint32(2)

	c := keyManagementContext{
		ourKeyID:             ourKeyID,
		theirKeyID:           theirKeyID,
		theirCurrentDHPubKey: big.NewInt(1),
		ourCurrentDHKeys: dhKeyPair{
			priv: big.NewInt(1),
			pub:  big.NewInt(1),
		},
	}
	keys, _ := c.calculateDHSessionKeys(ourKeyID, theirKeyID)

	expectedMACKeys := macKeyUsage{
		ourKeyID:     ourKeyID,
		theirKeyID:   theirKeyID,
		sendingKey:   keys.sendingMACKey,
		receivingKey: keys.receivingMACKey,
	}

	assertDeepEquals(t, len(c.macKeyHistory.items), 1)
	assertDeepEquals(t, c.macKeyHistory.items[0], expectedMACKeys)
}

func Test_calculateDHSessionKeys_failsWhenOurKeyIsUnknown(t *testing.T) {
	c := keyManagementContext{
		ourKeyID:   1,
		theirKeyID: 1,
	}

	_, err := c.calculateDHSessionKeys(2, 1)
	assertDeepEquals(t, err, errors.New("otr: unexpected ourKeyID 2"))

	_, err = c.calculateDHSessionKeys(1, 3)
	assertDeepEquals(t, err, errors.New("otr: unexpected theirKeyID 3"))
}

func Test_calculateAKEKeys(t *testing.T) {
	ssid, revealSigKeys, signatureKeys := calculateAKEKeys(expectedSharedSecret)

	assertDeepEquals(t, ssid[:], bytesFromHex("9cee5d2c7edbc86d"))
	assertDeepEquals(t, revealSigKeys.c[:], bytesFromHex("5745340b350364a02a0ac1467a318dcc"))
	assertDeepEquals(t, signatureKeys.c[:], bytesFromHex("d942cc80b66503414c05e3752d9ba5c4"))
	assertDeepEquals(t, revealSigKeys.m1[:], bytesFromHex("d3251498fb9d977d07392a96eafb8c048d6bc67064bd7da72aa38f20f87a2e3d"))
	assertDeepEquals(t, revealSigKeys.m2[:], bytesFromHex("79c101a78a6c5819547a36b4813c84a8ac553d27a5d4b58be45dd0f3a67d3ca6"))
	assertDeepEquals(t, signatureKeys.m1[:], bytesFromHex("b6254b8eab0ad98152949454d23c8c9b08e4e9cf423b27edc09b1975a76eb59c"))
	assertDeepEquals(t, signatureKeys.m2[:], bytesFromHex("954be27015eeb0455250144d906e83e7d329c49581aea634c4189a3c981184f5"))
}

func Test_rotateTheirKey_rotatesTheirKeysWhenWeReceiveANewPubKey(t *testing.T) {
	senderKey := uint32(1)
	currentPubKey := big.NewInt(9)
	receivedKey := big.NewInt(99)

	c := keyManagementContext{
		theirKeyID:           senderKey,
		theirCurrentDHPubKey: currentPubKey,
	}

	c.rotateTheirKey(senderKey, receivedKey)

	assertEquals(t, c.theirKeyID, senderKey+1)
	assertDeepEquals(t, c.theirPreviousDHPubKey, currentPubKey)
	assertDeepEquals(t, c.theirCurrentDHPubKey, receivedKey)
}

func Test_rotateTheirKey_doesNotRotateIfWeDontReceiveTheCurrentSenderKey(t *testing.T) {
	senderKey := uint32(1)
	previousPubKey := big.NewInt(8)
	currentPubKey := big.NewInt(9)
	receivedKey := big.NewInt(99)

	c := keyManagementContext{
		theirKeyID:            senderKey,
		theirPreviousDHPubKey: previousPubKey,
		theirCurrentDHPubKey:  currentPubKey,
	}

	c.rotateTheirKey(senderKey+1, receivedKey)

	assertEquals(t, c.theirKeyID, senderKey)
	assertDeepEquals(t, c.theirPreviousDHPubKey, previousPubKey)
	assertDeepEquals(t, c.theirCurrentDHPubKey, currentPubKey)
}

func Test_rotateOurKeys_rotateOurCurrentDHKeys(t *testing.T) {
	recipientKeyID := uint32(1)

	c := keyManagementContext{
		ourKeyID: recipientKeyID,
		ourCurrentDHKeys: dhKeyPair{
			pub:  fixedgx,
			priv: fixedx,
		},
	}

	c.rotateOurKeys(recipientKeyID, fixedy)

	assertEquals(t, c.ourKeyID, recipientKeyID+1)
	assertDeepEquals(t, c.ourPreviousDHKeys.priv, fixedx)
	assertDeepEquals(t, c.ourPreviousDHKeys.pub, fixedgx)
	assertDeepEquals(t, c.ourCurrentDHKeys.priv, fixedy)
	assertDeepEquals(t, c.ourCurrentDHKeys.pub, fixedgy)
}

func Test_rotateOurKeys_doesNotRotateIfWeDontReceiveOurCurrentKeyID(t *testing.T) {
	var nilB *big.Int
	recipientKeyID := uint32(1)

	c := keyManagementContext{
		ourKeyID: recipientKeyID,
		ourCurrentDHKeys: dhKeyPair{
			pub:  fixedgx,
			priv: fixedx,
		},
	}

	c.rotateOurKeys(recipientKeyID+1, fixedy)

	assertEquals(t, c.ourKeyID, recipientKeyID)
	assertEquals(t, c.ourPreviousDHKeys.priv, nilB)
	assertEquals(t, c.ourPreviousDHKeys.pub, nilB)
	assertDeepEquals(t, c.ourCurrentDHKeys.priv, fixedx)
	assertDeepEquals(t, c.ourCurrentDHKeys.pub, fixedgx)
}

func Test_revealMACKeys_ForgotOldKeysAfterBeenCalled(t *testing.T) {
	oldMACKeys := []macKey{
		macKey{0x00, 0x01, 0x02, 0x03, 0x00, 0x01, 0x02, 0x03, 0x00, 0x01, 0x02, 0x03, 0x00, 0x01, 0x02, 0x03, 0x00, 0x01, 0x02, 0x03},
	}
	c := keyManagementContext{
		oldMACKeys: oldMACKeys,
	}

	maKeys := c.revealMACKeys()

	assertDeepEquals(t, maKeys, oldMACKeys)
	assertDeepEquals(t, c.oldMACKeys, []macKey{})
}

func Test_rotateTheirKey_revealAllMACKeysAssociatedWithTheirPreviousPubKey(t *testing.T) {
	k := macKey{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	k1 := macKey{0x01, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	k2 := macKey{0x02, 0x02, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}

	expectedMACKeys := []macKey{
		k1, k2,
		k1, k2,
	}

	c := keyManagementContext{
		theirKeyID:            2,
		theirPreviousDHPubKey: big.NewInt(1),
	}

	c.macKeyHistory = macKeyHistory{
		items: []macKeyUsage{
			macKeyUsage{theirKeyID: 1, sendingKey: k1, receivingKey: k2},
			macKeyUsage{theirKeyID: 2, sendingKey: k, receivingKey: k},
			macKeyUsage{theirKeyID: 1, sendingKey: k1, receivingKey: k2},
		},
	}

	c.rotateTheirKey(2, big.NewInt(2))

	assertDeepEquals(t, c.oldMACKeys, expectedMACKeys)
	assertDeepEquals(t, len(c.macKeyHistory.items), 1)
	assertDeepEquals(t, c.macKeyHistory.items[0].sendingKey, k)
}

func Test_rotateOurKey_revealAllMACKeysAssociatedWithOurPreviousPubKey(t *testing.T) {
	k := macKey{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	k1 := macKey{0x01, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	k2 := macKey{0x02, 0x02, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}

	expectedMACKeys := []macKey{
		k1, k2,
		k1, k2,
	}

	c := keyManagementContext{
		ourKeyID: 2,
		ourPreviousDHKeys: dhKeyPair{
			priv: big.NewInt(1),
			pub:  big.NewInt(2),
		},
	}

	c.macKeyHistory = macKeyHistory{
		items: []macKeyUsage{
			macKeyUsage{ourKeyID: 1, sendingKey: k1, receivingKey: k2},
			macKeyUsage{ourKeyID: 2, sendingKey: k, receivingKey: k},
			macKeyUsage{ourKeyID: 1, sendingKey: k1, receivingKey: k2},
		},
	}

	c.rotateOurKeys(2, big.NewInt(2))

	assertDeepEquals(t, c.oldMACKeys, expectedMACKeys)
	assertDeepEquals(t, len(c.macKeyHistory.items), 1)
	assertDeepEquals(t, c.macKeyHistory.items[0].sendingKey, k)
}
