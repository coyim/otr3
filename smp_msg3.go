package otr3

import (
	"errors"
	"math/big"
)

type smp3 struct {
	x              *big.Int
	r4, r5, r6, r7 *big.Int
	msg            smpMessage3
}

type smpMessage3 struct {
	g2, g3     *big.Int
	pa, qa     *big.Int
	cp         *big.Int
	d5, d6, d7 *big.Int
	ra         *big.Int
	cr         *big.Int
	qaqb, papb *big.Int
}

func (c *context) generateThirdParameters() smp3 {
	b := make([]byte, c.parameterLength())
	s := smp3{}
	s.r4 = c.randMPI(b)
	s.r5 = c.randMPI(b)
	s.r6 = c.randMPI(b)
	s.r7 = c.randMPI(b)
	return s
}

func calculateMessageThree(s smp3, s1 smp1, m2 smpMessage2) smpMessage3 {
	var m smpMessage3

	m.g2 = modExp(m2.g2b, s1.a2)
	m.g3 = modExp(m2.g3b, s1.a3)

	m.pa = modExp(m.g3, s.r4)
	m.qa = mulMod(modExp(g1, s.r4), modExp(m.g2, s.x), p)

	m.cp = hashMPIsBN(nil, 6, modExp(m.g3, s.r5), mulMod(modExp(g1, s.r5), modExp(m.g2, s.r6), p))
	m.d5 = generateDZKP(s.r5, s.r4, m.cp)
	m.d6 = generateDZKP(s.r6, s.x, m.cp)

	m.qaqb = divMod(m.qa, m2.qb, p)
	m.ra = modExp(m.qaqb, s1.a3)

	m.cr = hashMPIsBN(nil, 7, modExp(g1, s.r7), modExp(m.qaqb, s.r7))
	m.d7 = subMod(s.r7, mul(s1.a3, m.cr), q)

	m.papb = divMod(m.pa, m2.pb, p)

	return m
}

func (c *context) generateSMPThirdParameters(secret *big.Int, s1 smp1, m2 smpMessage2) smp3 {
	s := c.generateThirdParameters()
	s.x = secret
	s.msg = calculateMessageThree(s, s1, m2)
	return s
}

func (c *context) verifySMP3Parameters(msg1 smpMessage1, msg smpMessage3) error {
	if !c.isGroupElement(msg.pa) {
		return errors.New("Pa is an invalid group element")
	}

	if !c.isGroupElement(msg.qa) {
		return errors.New("Qa is an invalid group element")
	}

	if !c.isGroupElement(msg.ra) {
		return errors.New("Ra is an invalid group element")
	}

	if !verifyZKP3(msg.cp, msg.g2, msg.g3, msg.d5, msg.d6, msg.pa, msg.qa, 6) {
		return errors.New("cP is not a valid zero knowledge proof")
	}

	if !verifyZKP4(msg.cr, msg1.g3a, msg.d7, msg.qaqb, msg.ra, 7) {
		return errors.New("cR is not a valid zero knowledge proof")
	}

	return nil
}

func (c *context) verifySMP3ProtocolSuccess(s2 smp2, msg smpMessage3) error {
	rab := modExp(msg.ra, s2.b3)
	if !eq(rab, msg.papb) {
		return errors.New("protocol failed: x != y")
	}

	return nil
}
