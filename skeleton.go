package otr3

import (
	"io"
	"math/big"
)

type context struct {
	version      otrVersion
	Rand         io.Reader
	currentState smpState
}

func newContext(v otrVersion, rand io.Reader) *context {
	return &context{version: v, Rand: rand, currentState: smpStateExpect1{}}
}

type otrVersion interface {
	parameterLength() int
	isGroupElement(n *big.Int) bool
}

type conversation interface {
	send(message []byte)
	receive(message []byte) error
}

func (c *context) send(message []byte) {
	// FIXME Dummy for now
}

// NOTE it only accepts TLVs
func (c *context) receive(message []byte) error {
	var err error
	m := parseTLV(message)
	c.currentState, err = m.receivedMessage(c.currentState)
	return err
}

func extractTLVs(data []byte) [][]byte {
	return nil
}

func stripPlaintext(data []byte) []byte {
	return nil
}

func (c *context) rand() io.Reader {
	return c.Rand
}

func (c *context) parameterLength() int {
	return c.version.parameterLength()
}

func (c *context) isGroupElement(n *big.Int) bool {
	return c.version.isGroupElement(n)
}

func (c *context) randMPI(buf []byte) *big.Int {
	io.ReadFull(c.rand(), buf)
	// TODO: errors here
	return new(big.Int).SetBytes(buf)
}
