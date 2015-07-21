package otr3

import (
	"errors"
	"math/big"
)

// FIXME should store g3b, (Pa / Pb), (Qa / Qb) and Ra
// after generating smpMessage3

type smp3 struct {
	x              *big.Int
	g3b            *big.Int
	r4, r5, r6, r7 *big.Int
	qaqb, papb     *big.Int
	msg            smpMessage3
}

type smpMessage3 struct {
	pa, qa     *big.Int
	cp         *big.Int
	d5, d6, d7 *big.Int
	ra         *big.Int
	cr         *big.Int
}

func (m smpMessage3) tlv() []byte {
	return genSMPTLV(4, m.pa, m.qa, m.cp, m.d5, m.d6, m.ra, m.cr, m.d7)
}

func (c *smpContext) generateThirdParameters() (s smp3, ok bool) {
	b := make([]byte, c.parameterLength())
	var ok1, ok2, ok3, ok4 bool
	s.r4, ok1 = c.randMPI(b)
	s.r5, ok2 = c.randMPI(b)
	s.r6, ok3 = c.randMPI(b)
	s.r7, ok4 = c.randMPI(b)
	return s, ok1 && ok2 && ok3 && ok4
}

func calculateMessageThree(s *smp3, s1 smp1, m2 smpMessage2) smpMessage3 {
	var m smpMessage3

	g2 := modExp(m2.g2b, s1.a2)
	g3 := modExp(m2.g3b, s1.a3)

	m.pa = modExp(g3, s.r4)
	m.qa = mulMod(modExp(g1, s.r4), modExp(g2, s.x), p)

	s.g3b = m2.g3b
	s.qaqb = divMod(m.qa, m2.qb, p)
	s.papb = divMod(m.pa, m2.pb, p)

	m.cp = hashMPIsBN(nil, 6, modExp(g3, s.r5), mulMod(modExp(g1, s.r5), modExp(g2, s.r6), p))
	m.d5 = generateDZKP(s.r5, s.r4, m.cp)
	m.d6 = generateDZKP(s.r6, s.x, m.cp)

	m.ra = modExp(s.qaqb, s1.a3)

	m.cr = hashMPIsBN(nil, 7, modExp(g1, s.r7), modExp(s.qaqb, s.r7))
	m.d7 = subMod(s.r7, mul(s1.a3, m.cr), q)

	return m
}

func (c *smpContext) generateSMP3(secret *big.Int, s1 smp1, m2 smpMessage2) (s smp3, ok bool) {
	if s, ok = c.generateThirdParameters(); !ok {
		return s, false
	}
	s.x = secret
	s.msg = calculateMessageThree(&s, s1, m2)
	return s, true
}

func (c *smpContext) verifySMP3(s2 smp2, msg smpMessage3) error {
	if !c.isGroupElement(msg.pa) {
		return errors.New("Pa is an invalid group element")
	}

	if !c.isGroupElement(msg.qa) {
		return errors.New("Qa is an invalid group element")
	}

	if !c.isGroupElement(msg.ra) {
		return errors.New("Ra is an invalid group element")
	}

	if !verifyZKP3(msg.cp, s2.g2, s2.g3, msg.d5, msg.d6, msg.pa, msg.qa, 6) {
		return errors.New("cP is not a valid zero knowledge proof")
	}

	//FIXME should it calculate it here?
	qaqb := divMod(msg.qa, s2.qb, p)

	if !verifyZKP4(msg.cr, s2.g3a, msg.d7, qaqb, msg.ra, 7) {
		return errors.New("cR is not a valid zero knowledge proof")
	}

	return nil
}

func (c *smpContext) verifySMP3ProtocolSuccess(s2 smp2, msg smpMessage3) error {
	papb := divMod(msg.pa, s2.msg.pb, p)

	rab := modExp(msg.ra, s2.b3)
	if !eq(rab, papb) {
		return errors.New("protocol failed: x != y")
	}

	return nil
}
