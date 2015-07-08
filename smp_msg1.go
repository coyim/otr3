package otr3

import (
	"errors"
	"math/big"
)

type smp1 struct {
	a2, a3 *big.Int
	r2, r3 *big.Int
	msg    smpMessage1
}

type smpMessage1 struct {
	g2a, g3a *big.Int
	c2, c3   *big.Int
	d2, d3   *big.Int
}

func (c *context) generateInitialParameters() smp1 {
	b := make([]byte, c.parameterLength())
	s := smp1{}
	s.a2 = c.randMPI(b)
	s.a3 = c.randMPI(b)
	s.r2 = c.randMPI(b)
	s.r3 = c.randMPI(b)
	return s
}

func generateMessageOneFor(s smp1) smpMessage1 {
	var m smpMessage1

	m.g2a = modExp(g1, s.a2)
	m.g3a = modExp(g1, s.a3)
	m.c2, m.d2 = generateZKP(s.r2, s.a2, 1)
	m.c3, m.d3 = generateZKP(s.r3, s.a3, 2)

	return m
}

func (c *context) generateSMPStartParameters() smp1 {
	s := c.generateInitialParameters()
	s.msg = generateMessageOneFor(s)
	return s
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
