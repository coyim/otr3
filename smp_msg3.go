package otr3

import "math/big"

type smp3 struct {
	x              *big.Int
	r4, r5, r6, r7 *big.Int
	msg            smpMessage3
}

type smpMessage3 struct {
	g2, g3 *big.Int
	pa, qa *big.Int
}

func (c *context) generateThirdParameters() smp3 {
	b := make([]byte, c.parameterLength(), c.parameterLength())
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

	return m
}

func (c *context) generateSMPThirdParameters(secret *big.Int, s1 smp1, m2 smpMessage2) smp3 {
	s := c.generateThirdParameters()
	s.x = secret
	s.msg = calculateMessageThree(s, s1, m2)
	return s
}
