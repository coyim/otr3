package otr3

import (
	"crypto/sha256"
	"errors"
	"math/big"
)

const smpVersion = 1

type smp struct {
	a2, a3 *big.Int
	r2, r3 *big.Int
	msg1   smpMessage1
}

type smpMessage1 struct {
	g2a, g3a *big.Int
	c2, c3   *big.Int
	d2, d3   *big.Int
}

func generateSMPSecret(initiatorFingerprint, recipientFingerprint, ssid, secret []byte) []byte {
	h := sha256.New()
	h.Write([]byte{smpVersion})
	h.Write(initiatorFingerprint)
	h.Write(recipientFingerprint)
	h.Write(ssid)
	h.Write(secret)
	return h.Sum(nil)
}

func (c *context) generateSMPStartParameters() smp {
	result := smp{}

	randBuf := make([]byte, c.parameterLength(), c.parameterLength())

	result.a2 = c.randMPI(randBuf)
	result.a3 = c.randMPI(randBuf)
	result.r2 = c.randMPI(randBuf)
	result.r3 = c.randMPI(randBuf)

	result.msg1.g2a = new(big.Int).Exp(g1, result.a2, p)
	result.msg1.g3a = new(big.Int).Exp(g1, result.a3, p)

	result.msg1.c2 = new(big.Int).SetBytes(hashMPIs(nil, 1, new(big.Int).Exp(g1, result.r2, p)))

	result.msg1.d2 = new(big.Int).Mul(result.a2, result.msg1.c2)
	result.msg1.d2.Sub(result.r2, result.msg1.d2)
	result.msg1.d2.Mod(result.msg1.d2, q)

	result.msg1.c3 = new(big.Int).SetBytes(hashMPIs(nil, 2, new(big.Int).Exp(g1, result.r3, p)))

	result.msg1.d3 = new(big.Int).Mul(result.a3, result.msg1.c3)
	result.msg1.d3.Sub(result.r3, result.msg1.d3)
	result.msg1.d3.Mod(result.msg1.d3, q)

	return result
}

func (c *context) verifySMPStartParameters(msg smpMessage1) error {
	if !c.isGroupElement(msg.g2a) {
		return errors.New("g2a is an invalid group element")
	}
	if !c.isGroupElement(msg.g3a) {
		return errors.New("g3a is an invalid group element")
	}

	r := new(big.Int).Exp(g1, msg.d2, p)
	s := new(big.Int).Exp(msg.g2a, msg.c2, p)
	r.Mul(r, s)
	r.Mod(r, p)
	t := new(big.Int).SetBytes(hashMPIs(nil, 1, r))
	if msg.c2.Cmp(t) != 0 {
		return errors.New("c2 is not a valid zero knowledge proof")
	}

	r.Exp(g1, msg.d3, p)
	s.Exp(msg.g3a, msg.c3, p)
	r.Mul(r, s)
	r.Mod(r, p)
	t.SetBytes(hashMPIs(nil, 2, r))
	if msg.c3.Cmp(t) != 0 {
		return errors.New("c3 is not a valid zero knowledge proof")
	}

	return nil
}
