package otr3

import (
	"crypto/aes"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/binary"
	"hash"
	"io"
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
	extraKey                       [sha256.Size]byte
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

type keyPairCounter struct {
	ourKeyID, theirKeyID     uint32
	ourCounter, theirCounter uint64
}

type counterHistory struct {
	counters []*keyPairCounter
}

func (h *counterHistory) findCounterFor(ourKeyID, theirKeyID uint32) *keyPairCounter {
	for _, c := range h.counters {
		if c.ourKeyID == ourKeyID && c.theirKeyID == theirKeyID {
			return c
		}
	}

	c := &keyPairCounter{
		ourKeyID:   ourKeyID,
		theirKeyID: theirKeyID,
	}

	h.counters = append(h.counters, c)
	return c
}

type keyManagementContext struct {
	ourKeyID, theirKeyID                        uint32
	ourCurrentDHKeys, ourPreviousDHKeys         dhKeyPair
	theirCurrentDHPubKey, theirPreviousDHPubKey *big.Int

	ourCounter uint64

	counterHistory counterHistory
	macKeyHistory  macKeyHistory
	oldMACKeys     []macKey
}

func (k *keyManagementContext) setTheirCurrentDHPubKey(key *big.Int) {
	k.theirCurrentDHPubKey = setBigInt(k.theirCurrentDHPubKey, key)
}

func (k *keyManagementContext) setOurCurrentDHKeys(priv *big.Int, pub *big.Int) {
	k.ourCurrentDHKeys.priv = setBigInt(k.ourCurrentDHKeys.priv, priv)
	k.ourCurrentDHKeys.pub = setBigInt(k.ourCurrentDHKeys.pub, pub)
}

func (k *keyManagementContext) checkMessageCounter(message dataMsg) error {
	counter := k.counterHistory.findCounterFor(message.recipientKeyID, message.senderKeyID)
	theirNextCounter := binary.BigEndian.Uint64(message.topHalfCtr[:])

	if theirNextCounter <= counter.theirCounter {
		return ErrGPGConflict
	}

	counter.theirCounter = theirNextCounter
	return nil
}

func (k *keyManagementContext) revealMACKeys() []macKey {
	ret := k.oldMACKeys
	k.oldMACKeys = []macKey{}
	return ret
}

func (k *keyManagementContext) generateNewDHKeyPair(randomness io.Reader) error {
	newPrivKey, err := randSizedMPI(randomness, 40)
	if err != nil {
		return err
	}

	k.ourPreviousDHKeys.wipe()
	k.ourPreviousDHKeys = k.ourCurrentDHKeys

	k.ourCurrentDHKeys = dhKeyPair{
		priv: newPrivKey,
		pub:  modExp(g1, newPrivKey),
	}
	k.ourKeyID++
	return nil
}

func (k *keyManagementContext) revealMACKeysForOurPreviousKeyID() {
	keys := k.macKeyHistory.forgetMACKeysForOurKey(k.ourKeyID - 1)
	k.oldMACKeys = append(k.oldMACKeys, keys...)
}

func (c *Conversation) rotateKeys(dataMessage dataMsg) error {
	if err := c.keys.rotateOurKeys(dataMessage.recipientKeyID, c.rand()); err != nil {
		return err
	}
	c.keys.rotateTheirKey(dataMessage.senderKeyID, dataMessage.y)

	return nil
}

func (k *keyManagementContext) rotateOurKeys(recipientKeyID uint32, randomness io.Reader) error {
	if recipientKeyID == k.ourKeyID {
		k.revealMACKeysForOurPreviousKeyID()
		return k.generateNewDHKeyPair(randomness)
	}
	return nil
}

func (k *keyManagementContext) revealMACKeysForTheirPreviousKeyID() {
	keys := k.macKeyHistory.forgetMACKeysForTheirKey(k.theirKeyID - 1)
	k.oldMACKeys = append(k.oldMACKeys, keys...)
}

func (k *keyManagementContext) rotateTheirKey(senderKeyID uint32, pubDHKey *big.Int) {
	if senderKeyID == k.theirKeyID {
		k.revealMACKeysForTheirPreviousKeyID()

		k.theirPreviousDHPubKey = k.theirCurrentDHPubKey
		k.theirCurrentDHPubKey = pubDHKey
		k.theirKeyID++
	}
}

func (k *keyManagementContext) calculateDHSessionKeys(ourKeyID, theirKeyID uint32) (sessionKeys, error) {
	var ret sessionKeys

	ourPrivKey, ourPubKey, err := k.pickOurKeys(ourKeyID)
	if err != nil {
		return ret, err
	}

	theirPubKey, err := k.pickTheirKey(theirKeyID)
	if err != nil {
		return ret, err
	}

	ret = calculateDHSessionKeys(ourPrivKey, ourPubKey, theirPubKey)
	k.macKeyHistory.addKeys(ourKeyID, theirKeyID, ret.receivingMACKey)

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

	copy(ret.extraKey[:], h(0xFF, secbytes, sha256.New()))

	return ret
}

func (k *keyManagementContext) pickOurKeys(ourKeyID uint32) (privKey, pubKey *big.Int, err error) {
	if ourKeyID == 0 || k.ourKeyID == 0 {
		return nil, nil, ErrGPGConflict
	}

	switch ourKeyID {
	case k.ourKeyID:
		privKey, pubKey = k.ourCurrentDHKeys.priv, k.ourCurrentDHKeys.pub
	case k.ourKeyID - 1:
		privKey, pubKey = k.ourPreviousDHKeys.priv, k.ourPreviousDHKeys.pub
	default:
		err = ErrGPGConflict
	}

	return privKey, pubKey, err
}

func (k *keyManagementContext) pickTheirKey(theirKeyID uint32) (pubKey *big.Int, err error) {
	if theirKeyID == 0 || k.theirKeyID == 0 {
		return nil, ErrGPGConflict
	}

	switch theirKeyID {
	case k.theirKeyID:
		pubKey = k.theirCurrentDHPubKey
	case k.theirKeyID - 1:
		if k.theirPreviousDHPubKey == nil {
			err = ErrGPGConflict
		} else {
			pubKey = k.theirPreviousDHPubKey
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
