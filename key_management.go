package otr3

import (
	"crypto/aes"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/binary"
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

	ourCounter   uint64
	theirCounter uint64

	macKeyHistory macKeyHistory
	oldMACKeys    []macKey
}

type macKeyUsage struct {
	ourKeyID, theirKeyID uint32
	receivingKey         macKey
}

type macKeyHistory struct {
	items []macKeyUsage
}

func (h *macKeyHistory) deleteKeysAt(del ...int) {
	for j := len(del) - 1; j >= 0; j-- {
		l := len(h.items)
		h.items[del[j]], h.items = h.items[l-1], h.items[:l-1]
	}
}

func (h *macKeyHistory) addKeys(ourKeyID uint32, theirKeyID uint32, receivingMACKey macKey) {
	macKeys := macKeyUsage{
		ourKeyID:     ourKeyID,
		theirKeyID:   theirKeyID,
		receivingKey: receivingMACKey,
	}
	h.items = append(h.items, macKeys)
}

func (h *macKeyHistory) forgetMACKeysForOurKey(ourKeyID uint32) []macKey {
	var ret []macKey
	var del []int

	for i, k := range h.items {
		if k.ourKeyID == ourKeyID {
			ret = append(ret, k.receivingKey)
			del = append(del, i)
		}
	}

	h.deleteKeysAt(del...)

	return ret
}

func (h *macKeyHistory) forgetMACKeysForTheirKey(theirKeyID uint32) []macKey {
	var ret []macKey
	var del []int

	for i, k := range h.items {
		if k.theirKeyID == theirKeyID {
			ret = append(ret, k.receivingKey)
			del = append(del, i)
		}
	}

	h.deleteKeysAt(del...)

	return ret
}

func (c *keyManagementContext) checkMessageCounter(message dataMsg) error {
	theirNextCounter := binary.BigEndian.Uint64(message.topHalfCtr[:])

	if theirNextCounter <= c.theirCounter {
		return ErrGPGConflict
	}

	c.theirCounter = theirNextCounter
	return nil
}

func (c *keyManagementContext) revealMACKeys() []macKey {
	ret := c.oldMACKeys
	c.oldMACKeys = []macKey{}
	return ret
}

func (c *keyManagementContext) generateNewDHKeyPair(newPrivKey *big.Int) {
	c.ourPreviousDHKeys.wipe()
	c.ourPreviousDHKeys = c.ourCurrentDHKeys

	c.ourCurrentDHKeys = dhKeyPair{
		priv: newPrivKey,
		pub:  modExp(g1, newPrivKey),
	}
	c.ourKeyID++
}

func (c *keyManagementContext) revealMACKeysForOurPreviousKeyID() {
	keys := c.macKeyHistory.forgetMACKeysForOurKey(c.ourKeyID - 1)
	c.oldMACKeys = append(c.oldMACKeys, keys...)
}

func (c *Conversation) rotateKeys(dataMessage dataMsg) error {
	x, err := c.randMPI(make([]byte, 40))
	if err != nil {
		//TODO: what should we do?
		//This is one kind of error that breaks the encrypted channel. I believe we
		//should change the msgState to != encrypted
		return err
	}

	c.keys.rotateOurKeys(dataMessage.recipientKeyID, x)
	c.keys.rotateTheirKey(dataMessage.senderKeyID, dataMessage.y)

	return nil
}

func (c *keyManagementContext) rotateOurKeys(recipientKeyID uint32, newPrivKey *big.Int) {
	if recipientKeyID == c.ourKeyID {
		c.revealMACKeysForOurPreviousKeyID()
		c.generateNewDHKeyPair(newPrivKey)
	}
}

func (c *keyManagementContext) revealMACKeysForTheirPreviousKeyID() {
	keys := c.macKeyHistory.forgetMACKeysForTheirKey(c.theirKeyID - 1)
	c.oldMACKeys = append(c.oldMACKeys, keys...)
}

func (c *keyManagementContext) rotateTheirKey(senderKeyID uint32, pubDHKey *big.Int) {
	if senderKeyID == c.theirKeyID {
		c.revealMACKeysForTheirPreviousKeyID()

		c.theirPreviousDHPubKey = c.theirCurrentDHPubKey
		c.theirCurrentDHPubKey = pubDHKey
		c.theirKeyID++
	}
}

func (c *keyManagementContext) calculateDHSessionKeys(ourKeyID, theirKeyID uint32) (sessionKeys, error) {
	var ret sessionKeys

	ourPrivKey, ourPubKey, err := c.pickOurKeys(ourKeyID)
	if err != nil {
		return ret, err
	}

	theirPubKey, err := c.pickTheirKey(theirKeyID)
	if err != nil {
		return ret, err
	}

	ret = calculateDHSessionKeys(ourPrivKey, ourPubKey, theirPubKey)
	c.macKeyHistory.addKeys(ourKeyID, theirKeyID, ret.receivingMACKey)

	return ret, nil
}

func calculateDHSessionKeys(ourPrivKey, ourPubKey, theirPubKey *big.Int) sessionKeys {
	var ret sessionKeys
	var sendbyte, recvbyte byte

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

	return ret
}

func (c *keyManagementContext) pickOurKeys(ourKeyID uint32) (privKey, pubKey *big.Int, err error) {
	if ourKeyID == 0 || c.ourKeyID == 0 {
		return nil, nil, ErrGPGConflict
	}

	switch ourKeyID {
	case c.ourKeyID:
		privKey, pubKey = c.ourCurrentDHKeys.priv, c.ourCurrentDHKeys.pub
	case c.ourKeyID - 1:
		privKey, pubKey = c.ourPreviousDHKeys.priv, c.ourPreviousDHKeys.pub
	default:
		err = ErrGPGConflict
	}

	return privKey, pubKey, err
}

func (c *keyManagementContext) pickTheirKey(theirKeyID uint32) (pubKey *big.Int, err error) {
	if theirKeyID == 0 || c.theirKeyID == 0 {
		return nil, ErrGPGConflict
	}

	switch theirKeyID {
	case c.theirKeyID:
		pubKey = c.theirCurrentDHPubKey
	case c.theirKeyID - 1:
		if c.theirPreviousDHPubKey == nil {
			err = ErrGPGConflict
		} else {
			pubKey = c.theirPreviousDHPubKey
		}
	default:
		err = ErrGPGConflict
	}

	return pubKey, err
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
