package otr3

import (
	"crypto/sha256"
	"errors"
	"math/big"
)

type message interface {
	serialize() []byte
	deserialize(msg []byte) error
}

type dhCommit struct {
	protocolVersion     uint16
	headerLen           int
	needInstanceTag     bool
	gx                  *big.Int
	hashedGx            [sha256.Size]byte
	encryptedGx         []byte
	senderInstanceTag   uint32
	receiverInstanceTag uint32
}

func (c *dhCommit) serialize() []byte {
	var out []byte
	out = appendShort(out, c.protocolVersion)
	out = append(out, msgTypeDHCommit)
	if c.needInstanceTag {
		out = appendWord(out, c.senderInstanceTag)
		out = appendWord(out, c.receiverInstanceTag)
	}
	out = appendData(out, c.encryptedGx)
	if c.hashedGx == [sha256.Size]byte{} {
		c.hashedGx = sha256Sum(appendMPI(nil, c.gx))
	}
	out = appendData(out, c.hashedGx[:])

	return out
}

func (c *dhCommit) deserialize(msg []byte) error {
	if len(msg) < c.headerLen {
		return errors.New("otr: invalid OTR message")
	}

	var ok1 bool
	msg, c.encryptedGx, ok1 = extractData(msg[c.headerLen:])
	_, h, ok2 := extractData(msg)
	if !ok1 || !ok2 {
		return errors.New("otr: corrupt DH commit message")
	}
	copy(c.hashedGx[:], h)
	return nil
}

type dhKey struct {
	protocolVersion     uint16
	headerLen           int
	needInstanceTag     bool
	gy                  *big.Int
	senderInstanceTag   uint32
	receiverInstanceTag uint32
}

func (c *dhKey) serialize() []byte {
	// TODO: errors?
	var out []byte

	out = appendShort(out, c.protocolVersion)
	out = append(out, msgTypeDHKey)

	if c.needInstanceTag {
		out = appendWord(out, c.senderInstanceTag)
		out = appendWord(out, c.receiverInstanceTag)
	}

	out = appendMPI(out, c.gy)

	return out
}
