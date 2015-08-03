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

func (c *Conversation) randMPI(buf []byte) (*big.Int, error) {
	if _, err := io.ReadFull(c.rand(), buf); err != nil {
		return nil, errShortRandomRead
	}

	return new(big.Int).SetBytes(buf), nil
}

func (c *Conversation) randomInto(b []byte) error {
	if _, err := io.ReadFull(c.rand(), b); err != nil {
		return errShortRandomRead
	}
	return nil
}
