package otr3

import (
	"errors"
	"math/big"
)

type smp2 struct {
	y                  *big.Int
	b2, b3             *big.Int
	r2, r3, r4, r5, r6 *big.Int
	msg                smpMessage2
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

func (c *context) generateSecondaryParameters() smp2 {
	b := make([]byte, c.parameterLength())
	s := smp2{}
	s.b2 = c.randMPI(b)
	s.b3 = c.randMPI(b)
	s.r2 = c.randMPI(b)
	s.r3 = c.randMPI(b)
	s.r4 = c.randMPI(b)
	s.r5 = c.randMPI(b)
	s.r6 = c.randMPI(b)
	return s
}

func generateMessageTwoFor(s smp2, s1 smpMessage1) smpMessage2 {
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

func (c *context) generateSMPSecondParameters(secret *big.Int, s1 smpMessage1) smp2 {
	s := c.generateSecondaryParameters()
	s.y = secret
	s.msg = generateMessageTwoFor(s, s1)
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
