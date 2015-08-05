package otr3

import "math/big"

func (p *dhKeyPair) wipe() {
	if p == nil {
		return
	}

	wipeBigInt(p.pub)
	wipeBigInt(p.priv)
	p.pub = nil
	p.priv = nil
}

func zeroes(n int) []byte {
	return make([]byte, n)
}

func wipeBytes(b []byte) {
	copy(b, zeroes(len(b)))
}

func wipeBigInt(k *big.Int) {
	if k == nil {
		return
	}

	k.SetBytes(zeroes(len(k.Bytes())))
}

func setBigInt(dst *big.Int, src *big.Int) *big.Int {
	wipeBigInt(dst)

	ret := big.NewInt(0)
	ret.Set(src)
	return ret
}
