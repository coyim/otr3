package otr3

import (
	"errors"
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
