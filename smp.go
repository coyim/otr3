package otr3

import (
	"crypto/sha256"
	"math/big"
)

const smpVersion = 1

type smp struct {
	a2, a3 *big.Int
	r2, r3 *big.Int
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

	return result
}
