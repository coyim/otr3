package otr3

import (
	"crypto/rand"
	"io"
	"math/big"
)

func (c *Conversation) rand() io.Reader {
	if c.Rand != nil {
		return c.Rand
	}
	return rand.Reader
}

func (c *Conversation) randMPI(buf []byte) (*big.Int, bool) {
	_, err := io.ReadFull(c.rand(), buf)

	if err != nil {
		return nil, false
	}

	return new(big.Int).SetBytes(buf), true
}

func (c *Conversation) randomInto(b []byte) error {
	if _, err := io.ReadFull(c.rand(), b); err != nil {
		return errShortRandomRead
	}
	return nil
}
