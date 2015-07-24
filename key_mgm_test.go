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
