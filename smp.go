package otr3

import (
	"crypto/sha256"
	"errors"
	"math/big"
)

const smpVersion = 1

type smpA struct {
	a2, a3 *big.Int
	r2, r3 *big.Int
	msg1   smpMessage1
}

type smpB struct {
	y                  *big.Int
	b2, b3             *big.Int
	r2, r3, r4, r5, r6 *big.Int
	msg2               smpMessage2
}

type smpMessage1 struct {
	g2a, g3a *big.Int
	c2, c3   *big.Int
	d2, d3   *big.Int
}

type smpMessage2 struct {
	g2b, g3b *big.Int
	c2, c3   *big.Int
	d2, d3   *big.Int
	g2, g3   *big.Int
	pb, qb   *big.Int
	cp       *big.Int
	d5, d6   *big.Int
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

func (c *context) generateInitialParameters() smpA {
	b := make([]byte, c.parameterLength(), c.parameterLength())
	s := smpA{}
	s.a2 = c.randMPI(b)
	s.a3 = c.randMPI(b)
	s.r2 = c.randMPI(b)
	s.r3 = c.randMPI(b)
	return s
}

func generateZKP(r, a *big.Int, ix byte) (c, d *big.Int) {
	c = hashMPIsBN(nil, ix, modExp(g1, r))
	d = subMod(r, mul(a, c), q)
	return
}

func generateMessageOneFor(s smpA) smpMessage1 {
	var m smpMessage1

	m.g2a = modExp(g1, s.a2)
	m.g3a = modExp(g1, s.a3)
	m.c2, m.d2 = generateZKP(s.r2, s.a2, 1)
	m.c3, m.d3 = generateZKP(s.r3, s.a3, 2)

	return m
}

func (c *context) generateSMPStartParameters() smpA {
	s := c.generateInitialParameters()
	s.msg1 = generateMessageOneFor(s)
	return s
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

func (c *context) verifySMPStartParameters(msg smpMessage1) error {
	if !c.isGroupElement(msg.g2a) {
		return errors.New("g2a is an invalid group element")
	}

	if !c.isGroupElement(msg.g3a) {
		return errors.New("g3a is an invalid group element")
	}

	if !verifyZKP(msg.d2, msg.g2a, msg.c2, 1) {
		return errors.New("c2 is not a valid zero knowledge proof")
	}

	if !verifyZKP(msg.d3, msg.g3a, msg.c3, 2) {
		return errors.New("c3 is not a valid zero knowledge proof")
	}

	return nil
}

func (c *context) generateSecondaryParameters() smpB {
	b := make([]byte, c.parameterLength(), c.parameterLength())
	s := smpB{}
	s.b2 = c.randMPI(b)
	s.b3 = c.randMPI(b)
	s.r2 = c.randMPI(b)
	s.r3 = c.randMPI(b)
	s.r4 = c.randMPI(b)
	s.r5 = c.randMPI(b)
	s.r6 = c.randMPI(b)
	return s
}

func generateMessageTwoFor(s smpB, s1 smpMessage1) smpMessage2 {
	var m smpMessage2

	m.g2b = modExp(g1, s.b2)
	m.g3b = modExp(g1, s.b3)

	m.c2, m.d2 = generateZKP(s.r2, s.b2, 3)
	m.c3, m.d3 = generateZKP(s.r3, s.b3, 4)

	m.g2 = modExp(s1.g2a, s.b2)
	m.g3 = modExp(s1.g3a, s.b3)

	m.pb = modExp(m.g3, s.r4)
	m.qb = mulMod(modExp(g1, s.r4), modExp(m.g2, s.y), p)

	m.cp = hashMPIsBN(nil, 5,
		modExp(m.g3, s.r5),
		mulMod(modExp(g1, s.r5), modExp(m.g2, s.r6), p))

	m.d5 = subMod(s.r5, mul(s.r4, m.cp), q)
	m.d6 = subMod(s.r6, mul(s.y, m.cp), q)

	return m
}

func (c *context) generateSMPSecondParameters(secret *big.Int, s1 smpMessage1) smpB {
	s := c.generateSecondaryParameters()
	s.y = secret
	s.msg2 = generateMessageTwoFor(s, s1)
	return s
}

func (c *context) verifySMPSecondParameters(msg smpMessage2) error {
	if !c.isGroupElement(msg.g2b) {
		return errors.New("g2b is an invalid group element")
	}

	if !c.isGroupElement(msg.g3b) {
		return errors.New("g3b is an invalid group element")
	}

	if !c.isGroupElement(msg.pb) {
		return errors.New("Pb is an invalid group element")
	}

	if !c.isGroupElement(msg.qb) {
		return errors.New("Qb is an invalid group element")
	}

	if !verifyZKP(msg.d2, msg.g2b, msg.c2, 3) {
		return errors.New("c2 is not a valid zero knowledge proof")
	}

	if !verifyZKP(msg.d3, msg.g3b, msg.c3, 4) {
		return errors.New("c3 is not a valid zero knowledge proof")
	}

	if !verifyZKP2(msg.g2, msg.g3, msg.d5, msg.d6, msg.pb, msg.qb, msg.cp, 5) {
		return errors.New("cP is not a valid zero knowledge proof")
	}

	return nil
}
