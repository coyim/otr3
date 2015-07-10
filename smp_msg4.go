package otr3

import (
	"errors"
	"math/big"
)

type smp4 struct {
	y   *big.Int
	r7  *big.Int
	msg smpMessage4
}

type smpMessage4 struct {
	cr *big.Int
	d7 *big.Int
	rb *big.Int
}

func (m *smpMessage4) tlv() []byte {
	return genSMPTLV(5, m.rb, m.cr, m.d7)
}

func (c *context) generateSMPFourthParameters(secret *big.Int, s2 smp2, msg3 smpMessage3) smp4 {
	s := c.generateFourthParameters()
	s.y = secret
	s.msg = calculateMessageFour(s, s2, msg3)
	return s
}

func (c *context) verifySMP4Parameters(s3 smp3, msg2 smpMessage2, msg smpMessage4) error {
	if !c.isGroupElement(msg.rb) {
		return errors.New("Rb is an invalid group element")
	}

	if !verifyZKP4(msg.cr, msg2.g3b, msg.d7, s3.qaqb, msg.rb, 8) {
		return errors.New("cR is not a valid zero knowledge proof")
	}

	return nil
}

func (c *context) generateFourthParameters() smp4 {
	b := make([]byte, c.parameterLength())
	s := smp4{}
	s.r7 = c.randMPI(b)
	return s
}

func calculateMessageFour(s smp4, s2 smp2, msg3 smpMessage3) smpMessage4 {
	var m smpMessage4

	qaqb := divMod(msg3.qa, s2.qb, p)

	m.rb = modExp(qaqb, s2.b3)
	m.cr = hashMPIsBN(nil, 8, modExp(g1, s.r7), modExp(qaqb, s.r7))
	m.d7 = subMod(s.r7, mul(s2.b3, m.cr), q)

	return m
}

func (c *context) verifySMP4ProtocolSuccess(s1 smp1, s3 smp3, msg smpMessage4) error {
	rab := modExp(msg.rb, s1.a3)
	if !eq(rab, s3.papb) {
		return errors.New("protocol failed: x != y")
	}

	return nil
}
