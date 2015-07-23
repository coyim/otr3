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

	ourCounter uint64
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

	sha := sha1.New()
	copy(ret.sendingAESKey[:], h(sendbyte, secbytes, sha))
	copy(ret.receivingAESKey[:], h(recvbyte, secbytes, sha))

	ret.sendingMACKey = sha1.Sum(ret.sendingAESKey[:])
	ret.receivingMACKey = sha1.Sum(ret.receivingAESKey[:])

	return ret, nil
}

func calculateAKEKeys(s *big.Int) (ssid [8]byte, revealSigKeys, signatureKeys akeKeys) {
	secbytes := appendMPI(nil, s)
	sha := sha256.New()
	keys := h(0x01, secbytes, sha)

	copy(ssid[:], h(0x00, secbytes, sha)[:8])
	copy(revealSigKeys.c[:], keys[:16])
	copy(signatureKeys.c[:], keys[16:])
	copy(revealSigKeys.m1[:], h(0x02, secbytes, sha))
	copy(revealSigKeys.m2[:], h(0x03, secbytes, sha))
	copy(signatureKeys.m1[:], h(0x04, secbytes, sha))
	copy(signatureKeys.m2[:], h(0x05, secbytes, sha))

	return
}

// h1() and h2() are the same
func h(b byte, secbytes []byte, h hash.Hash) []byte {
	h.Reset()
	h.Write([]byte{b})
	h.Write(secbytes[:])
	return h.Sum(nil)
}

//calculateSessionKeysWhenAKEIsCompleted (receiveRevealSig and recevieSig)
//rotateDhKeys
//rotateYKeys
