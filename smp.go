package otr3

import (
	"crypto/sha256"
	"math/big"
)

const smpVersion = 1

func generateSMPSecret(initiatorFingerprint, recipientFingerprint, ssid, secret []byte) []byte {
	h := sha256.New()
	h.Write([]byte{smpVersion})
	h.Write(initiatorFingerprint)
	h.Write(recipientFingerprint)
	h.Write(ssid)
	h.Write(secret)
	return h.Sum(nil)
}

func generateZKP(r, a *big.Int, ix byte) (c, d *big.Int) {
	c = hashMPIsBN(nil, ix, modExp(g1, r))
	d = subMod(r, mul(a, c), q)
	return
}

func verifyZKP(d, gen, c *big.Int, ix byte) bool {
	r := modExp(g1, d)
	s := modExp(gen, c)
	t := hashMPIsBN(nil, ix, mulMod(r, s, p))
	return eq(c, t)
}

func verifyZKP2(g2, g3, d5, d6, pb, qb, cp *big.Int, ix byte) bool {
	l := mulMod(
		modExp(g3, d5),
		modExp(pb, cp),
		p)
	r := mulMod(mul(modExp(g1, d5),
		modExp(g2, d6)),
		modExp(qb, cp),
		p)
	t := hashMPIsBN(nil, ix, l, r)
	return eq(cp, t)
}
