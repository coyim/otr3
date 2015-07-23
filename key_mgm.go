package otr3

import (
	"crypto/sha1"
	"fmt"
	"hash"
	"math/big"
)

type dhKeyPair struct {
	pub  *big.Int
	priv *big.Int
}

type sessionKeys struct {
	sendingAESKey, receivingAESKey [16]byte
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
	copy(ret.sendingAESKey[:], c.h1(h, sendbyte, secbytes))
	copy(ret.receivingAESKey[:], c.h1(h, recvbyte, secbytes))

	ret.sendingMACKey = sha1.Sum(ret.sendingAESKey[:])
	ret.receivingMACKey = sha1.Sum(ret.receivingAESKey[:])

	return ret, nil
}

func (c *keyManagementContext) h1(h hash.Hash, b byte, secbytes []byte) []byte {
	h.Reset()
	h.Write([]byte{b})
	h.Write(secbytes[:])
	return h.Sum(nil)
}
