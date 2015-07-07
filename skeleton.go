package otr3

import "io"

type context struct {
	version otrVersion
	Rand    io.Reader
}

type otrV2 struct{}
type otrV3 struct{}
type otrVersion interface{}

type conversation interface {
	send(message []byte)
	receive() []byte
}

func (c *context) send(message []byte) {
	// Dummy for now
}

func (c *context) receive() []byte {
	// Dummy for now
	return nil
}

func (c *context) rand() io.Reader {
	return c.Rand
}
