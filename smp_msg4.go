package otr3

import (
	"errors"
	"math/big"
)

type smp4State struct {
	y   *big.Int
	r7  *big.Int
	msg smp4Message
}

type smp4Message struct {
	cr *big.Int
	d7 *big.Int
	rb *big.Int
}

func (m smp4Message) tlv() tlv {
	return genSMPTLV(0x0005, m.rb, m.cr, m.d7)
}

func (c *conversation) generateSMP4(secret *big.Int, s2 smp2State, msg3 smp3Message) (smp4State, bool) {
	s, ok := c.generateSMP4Parameters()
	if !ok {
		return s, false
	}
	s.y = secret
	s.msg = generateSMP4Message(s, s2, msg3)
	return s, true
}

func (c *conversation) verifySMP4(s3 smp3State, msg smp4Message) error {
	if !c.version.isGroupElement(msg.rb) {
		return errors.New("Rb is an invalid group element")
	}

	if !verifyZKP4(msg.cr, s3.g3b, msg.d7, s3.qaqb, msg.rb, 8) {
		return errors.New("cR is not a valid zero knowledge proof")
	}

	return nil
}

func (c *conversation) generateSMP4Parameters() (s smp4State, ok bool) {
	b := make([]byte, c.version.parameterLength())
	s.r7, ok = c.randMPI(b)
	return
}

func generateSMP4Message(s smp4State, s2 smp2State, msg3 smp3Message) smp4Message {
	var m smp4Message

	qaqb := divMod(msg3.qa, s2.qb, p)

	m.rb = modExp(qaqb, s2.b3)
	m.cr = hashMPIsBN(nil, 8, modExp(g1, s.r7), modExp(qaqb, s.r7))
	m.d7 = subMod(s.r7, mul(s2.b3, m.cr), q)

	return m
}

func (c *conversation) verifySMP4ProtocolSuccess(s1 smp1State, s3 smp3State, msg smp4Message) error {
	rab := modExp(msg.rb, s1.a3)
	if !eq(rab, s3.papb) {
		return errors.New("protocol failed: x != y")
	}

	return nil
}
