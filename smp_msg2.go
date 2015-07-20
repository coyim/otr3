package otr3

import (
	"errors"
	"math/big"
)

// FIXME should store g3a*, g2, g3, b3, Pb and Qb
// after generating smpMessage2

type smp2 struct {
	y                  *big.Int
	b2, b3             *big.Int
	r2, r3, r4, r5, r6 *big.Int
	g2, g3             *big.Int
	g3a                *big.Int
	qb                 *big.Int
	msg                smpMessage2
}

type smpMessage2 struct {
	g2b, g3b *big.Int
	c2, c3   *big.Int
	d2, d3   *big.Int
	pb, qb   *big.Int
	cp       *big.Int
	d5, d6   *big.Int
}

func (m *smpMessage2) tlv() []byte {
	// TODO: errors?
	return genSMPTLV(3, m.g2b, m.c2, m.d2, m.g3b, m.c3, m.d3, m.pb, m.qb, m.cp, m.d5, m.d6)
}

func (c *otrContext) generateSecondaryParameters() smp2 {
	// TODO: errors?
	b := make([]byte, c.parameterLength())
	s := smp2{}
	s.b2, _ = c.randMPI(b)
	s.b3, _ = c.randMPI(b)
	s.r2, _ = c.randMPI(b)
	s.r3, _ = c.randMPI(b)
	s.r4, _ = c.randMPI(b)
	s.r5, _ = c.randMPI(b)
	s.r6, _ = c.randMPI(b)
	return s
}

func generateMessageTwoFor(s *smp2, s1 smpMessage1) smpMessage2 {
	// TODO: errors?
	var m smpMessage2

	m.g2b = modExp(g1, s.b2)
	m.g3b = modExp(g1, s.b3)

	m.c2, m.d2 = generateZKP(s.r2, s.b2, 3)
	m.c3, m.d3 = generateZKP(s.r3, s.b3, 4)

	s.g3a = s1.g3a
	s.g2 = modExp(s1.g2a, s.b2)
	s.g3 = modExp(s1.g3a, s.b3)

	m.pb = modExp(s.g3, s.r4)
	m.qb = mulMod(modExp(g1, s.r4), modExp(s.g2, s.y), p)

	m.cp = hashMPIsBN(nil, 5,
		modExp(s.g3, s.r5),
		mulMod(modExp(g1, s.r5), modExp(s.g2, s.r6), p))

	m.d5 = subMod(s.r5, mul(s.r4, m.cp), q)
	m.d6 = subMod(s.r6, mul(s.y, m.cp), q)

	return m
}

func (c *otrContext) generateSMPSecondParameters(secret *big.Int, s1 smpMessage1) smp2 {
	// TODO: errors?
	s := c.generateSecondaryParameters()
	s.y = secret
	s.msg = generateMessageTwoFor(&s, s1)
	s.qb = s.msg.qb
	return s
}

func (c *otrContext) verifySMPSecondParameters(s1 smp1, msg smpMessage2) error {
	// TODO: errors?
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

	g2 := modExp(msg.g2b, s1.a2)
	g3 := modExp(msg.g3b, s1.a3)

	if !verifyZKP2(g2, g3, msg.d5, msg.d6, msg.pb, msg.qb, msg.cp, 5) {
		return errors.New("cP is not a valid zero knowledge proof")
	}

	return nil
}
