package otr3

import (
	"math/big"
	"testing"
)

func Test_zeroes_generateZeroes(t *testing.T) {
	z := zeroes(5)
	assertDeepEquals(t, z, []byte{0, 0, 0, 0, 0})
}

func Test_wipeBytes_zeroesTheSlice(t *testing.T) {
	b := []byte{1, 2, 3, 4, 5}
	wipeBytes(b)

	assertDeepEquals(t, b, zeroes(len(b)))
}

func Test_wipeBigInt_numberIsZeroed(t *testing.T) {
	n := big.NewInt(3)
	wipeBigInt(n)
	assertEquals(t, n.Cmp(big.NewInt(0)), 0)
}

func Test_setBigInt_numberIsSet(t *testing.T) {
	n := big.NewInt(3)
	n = setBigInt(n, big.NewInt(5))
	assertEquals(t, n.Cmp(big.NewInt(5)), 0)
}

func Test_setBigInt_setWhenSourceIsNull(t *testing.T) {
	var n *big.Int
	n = setBigInt(n, big.NewInt(5))
	assertEquals(t, n.Cmp(big.NewInt(5)), 0)
}

func Test_wipe_macKey(t *testing.T) {
	k := macKey{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 8, 7, 6, 5}
	k.wipe()

	assertDeepEquals(t, k, macKey{})
}

func Test_wipe_keyManagementContext(t *testing.T) {
	keys := keyManagementContext{
		ourKeyID:   2,
		theirKeyID: 3,
		ourCurrentDHKeys: dhKeyPair{
			priv: big.NewInt(1),
			pub:  big.NewInt(2),
		},
		ourPreviousDHKeys: dhKeyPair{
			priv: big.NewInt(3),
			pub:  big.NewInt(4),
		},
		theirCurrentDHPubKey:  big.NewInt(5),
		theirPreviousDHPubKey: big.NewInt(6),
		ourCounter:            1,
		theirCounter:          2,
		macKeyHistory: macKeyHistory{
			items: []macKeyUsage{
				macKeyUsage{
					ourKeyID:     2,
					theirKeyID:   3,
					receivingKey: macKey{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 2, 3, 4},
				},
			},
		},
		oldMACKeys: []macKey{
			macKey{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 8, 7, 6, 5},
		},
	}

	keys.wipe()

	assertDeepEquals(t, keys, keyManagementContext{})
}
