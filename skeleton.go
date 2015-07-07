package otr3

import (
	"io"
	"math/big"
)

type context struct {
	version otrVersion
	Rand    io.Reader
}

type otrVersion interface {
	parameterLength() int
}

type conversation interface {
	send(message []byte)
	receive() []byte
}

func (c *context) send(message []byte) {
	// FIXME Dummy for now
}

func (c *context) receive() []byte {
	// FIXME Dummy for now
	return nil
}

func (c *context) rand() io.Reader {
	return c.Rand
}

func (c *context) parameterLength() int {
	return c.version.parameterLength()
}

func (c *context) randMPI(buf []byte) *big.Int {
	io.ReadFull(c.rand(), buf)
	// TODO: errors here
	return new(big.Int).SetBytes(buf)
}
