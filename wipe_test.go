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
