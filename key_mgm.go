package otr3

import (
	"crypto/aes"
	"crypto/sha1"
	"crypto/sha256"
	"fmt"
	"hash"
	"math/big"
)

type dhKeyPair struct {
	pub  *big.Int
	priv *big.Int
}

type akeKeys struct {
	c      [aes.BlockSize]byte
	m1, m2 [sha256.Size]byte
}

type sessionKeys struct {
	sendingAESKey, receivingAESKey [aes.BlockSize]byte
	sendingMACKey, receivingMACKey [sha1.Size]byte
}

type keyManagementContext struct {
	ourKeyID, theirKeyID                        uint32
	ourCurrentDHKeys, ourPreviousDHKeys         dhKeyPair
	theirCurrentDHPubKey, theirPreviousDHPubKey *big.Int
}

func (c *keyManagementContext) calculateDHSessionKeys(ourKeyID, theirKeyID uint32) (sessionKeys, error) {
	var ret sessionKeys
	var ourPubKey, ourPrivKey, theirPubKey *big.Int
	var sendbyte, recvbyte byte

	switch ourKeyID {
	case c.ourKeyID:
		ourPrivKey = c.ourCurrentDHKeys.priv
		ourPubKey = c.ourCurrentDHKeys.pub
	case c.ourKeyID - 1:
		ourPrivKey = c.ourPreviousDHKeys.priv
		ourPubKey = c.ourPreviousDHKeys.pub
	default:
		return ret, fmt.Errorf("otr: unexpected ourKeyID %d", ourKeyID)
	}

	switch theirKeyID {
	case c.theirKeyID:
		theirPubKey = c.theirCurrentDHPubKey
	case c.theirKeyID - 1:
		theirPubKey = c.theirPreviousDHPubKey
	default:
		return ret, fmt.Errorf("otr: unexpected theirKeyID %d", theirKeyID)
	}

	if gt(ourPubKey, theirPubKey) {
		//we are high end
		sendbyte, recvbyte = 0x01, 0x02
	} else {
		//we are low end
		sendbyte, recvbyte = 0x02, 0x01
	}

	s := new(big.Int).Exp(theirPubKey, ourPrivKey, p)
	secbytes := appendMPI(nil, s)

	h := sha1.New()
	copy(ret.sendingAESKey[:], c.h1(sendbyte, secbytes, h))
	copy(ret.receivingAESKey[:], c.h1(recvbyte, secbytes, h))

	ret.sendingMACKey = sha1.Sum(ret.sendingAESKey[:])
	ret.receivingMACKey = sha1.Sum(ret.receivingAESKey[:])

	return ret, nil
}

func (c *keyManagementContext) calculateAKEKeys(s *big.Int) (ssid [8]byte, revealSigKeys, signatureKeys akeKeys) {
	secbytes := appendMPI(nil, s)
	h := sha256.New()
	keys := c.h2(0x01, secbytes, h)

	copy(ssid[:], c.h2(0x00, secbytes, h)[:8])
	copy(revealSigKeys.c[:], keys[:16])
	copy(signatureKeys.c[:], keys[16:])
	copy(revealSigKeys.m1[:], c.h2(0x02, secbytes, h))
	copy(revealSigKeys.m2[:], c.h2(0x03, secbytes, h))
	copy(signatureKeys.m1[:], c.h2(0x04, secbytes, h))
	copy(signatureKeys.m2[:], c.h2(0x05, secbytes, h))

	return
}

func (*keyManagementContext) h(b byte, secbytes []byte, h hash.Hash) []byte {
	h.Reset()
	h.Write([]byte{b})
	h.Write(secbytes[:])
	return h.Sum(nil)
}

func (c *keyManagementContext) h1(b byte, secbytes []byte, h hash.Hash) []byte {
	return c.h(b, secbytes, h)
}

func (c *keyManagementContext) h2(b byte, secbytes []byte, h hash.Hash) []byte {
	return c.h(b, secbytes, h)
}
