package otr3

import (
	"bytes"
	"errors"
	"io"
	"math/big"
	"strconv"
)

var (
	errUnsupportedOTRVersion = errors.New("unsupported OTR version")
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
	Int() int
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

var queryMarker = []byte("?OTR")

func parseOTRQueryMessage(msg []byte) []int {
	ret := []int{}

	if bytes.HasPrefix(msg, queryMarker) {
		var p int
		versions := msg[len(queryMarker):]

		if versions[p] == '?' {
			ret = append(ret, 1)
			p++
		}

		if len(versions) > p && versions[p] == 'v' {
			for _, c := range versions[p:] {
				if v, err := strconv.Atoi(string(c)); err == nil {
					ret = append(ret, v)
				}
			}
		}
	}

	return ret
}

// This should be used by the xmpp-client to received OTR messages in plain
//TODO toSend needs fragmentation to be implemented
func (c *context) receive(message []byte) (toSend []byte, err error) {

	if bytes.HasPrefix(message, []byte(queryMarker)) {
		toSend, err = c.receiveOTRQueryMessage(message)
		return
	}

	//naive SMP parsing
	err = c.receiveSMPMessage(message)
	return
}

func generateIntanceTag() uint32 {
	//TODO generate this
	return 0x00000100 + 0x01
}

func (c *context) receiveOTRQueryMessage(message []byte) ([]byte, error) {
	if err := c.acceptOTRRequest(message); err != nil {
		return nil, err
	}

	ake := AKE{
		context: c,
	}

	return ake.dhCommitMessage()
}

func (c *context) acceptOTRRequest(msg []byte) error {
	version := 0
	versions := parseOTRQueryMessage(msg)

	for _, v := range versions {
		if v > version {
			version = v
		}
	}

	switch version {
	case 2:
		c.version = otrV2{}
	case 3:
		c.version = otrV3{}
	default:
		return errUnsupportedOTRVersion
	}

	return nil
}

func (c *context) receiveSMPMessage(message []byte) error {
	var err error
	m := parseTLV(message)
	c.currentState, err = m.receivedMessage(c.currentState)
	return err
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
