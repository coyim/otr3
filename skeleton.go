package otr3

type context struct{}

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
