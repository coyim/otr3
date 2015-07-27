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

type macKey [sha1.Size]byte

type sessionKeys struct {
	sendingAESKey, receivingAESKey [aes.BlockSize]byte
	sendingMACKey, receivingMACKey macKey
}

type keyManagementContext struct {
	ourKeyID, theirKeyID                        uint32
	ourCurrentDHKeys, ourPreviousDHKeys         dhKeyPair
	theirCurrentDHPubKey, theirPreviousDHPubKey *big.Int

	ourCounter uint64

	macKeyHistory macKeyHistory
	oldMACKeys    []macKey
}

type macKeyUsage struct {
	ourKeyID, theirKeyID     uint32
	sendingKey, receivingKey macKey
}

type macKeyHistory struct {
	items []macKeyUsage
}

func (h *macKeyHistory) deleteKeyAt(index int) {
	l := len(h.items)
	h.items[index], h.items = h.items[l-1], h.items[:l-1]
}

func (c *keyManagementContext) revealMACKeys() []macKey {
	ret := c.oldMACKeys
	c.oldMACKeys = []macKey{}
	return ret
}

func (c *keyManagementContext) generateNewDHKeyPair(newPrivKey *big.Int) {
	c.ourPreviousDHKeys = c.ourCurrentDHKeys
	c.ourCurrentDHKeys = dhKeyPair{
		priv: newPrivKey,
		pub:  modExp(g1, newPrivKey),
	}
	c.ourKeyID++
}

func (c *keyManagementContext) rotateOurKeys(recipientKeyID uint32, newPrivKey *big.Int) {
	if recipientKeyID == c.ourKeyID {
		//TODO: reveal MAC keys for c.ourPreviousDHKeys

		for index, key := range c.macKeyHistory.items {
			if key.ourKeyID == (recipientKeyID - 1) {
				c.oldMACKeys = append(c.oldMACKeys, key.sendingKey, key.receivingKey)

				c.macKeyHistory.deleteKeyAt(index)
			}
		}

		c.generateNewDHKeyPair(newPrivKey)
	}
}

func (c *keyManagementContext) rotateTheirKey(senderKeyID uint32, pubDHKey *big.Int) {
	if senderKeyID == c.theirKeyID {

		//reveal all previously used MAC keys for theirID
		for index, key := range c.macKeyHistory.items {
			if key.theirKeyID == (senderKeyID - 1) {
				c.oldMACKeys = append(c.oldMACKeys, key.sendingKey, key.receivingKey)

				c.macKeyHistory.deleteKeyAt(index)
			}
		}

		c.theirPreviousDHPubKey = c.theirCurrentDHPubKey
		c.theirCurrentDHPubKey = pubDHKey
		c.theirKeyID++
	}
}

func (c *keyManagementContext) calculateDHSessionKeys(ourKeyID, theirKeyID uint32) (sessionKeys, error) {
	var ret sessionKeys
	var ourPubKey, ourPrivKey, theirPubKey *big.Int
	var sendbyte, recvbyte byte

	if c.ourKeyID == 0 {
		ourPrivKey = c.ourCurrentDHKeys.priv
		ourPubKey = c.ourCurrentDHKeys.pub
	} else {
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
