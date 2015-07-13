package otr3

import (
	"io"
	"math/big"
	"strconv"
	"strings"
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

var queryMarker = "?OTR"

func parseOTRQueryMessage(msg string) []int {
	ret := []int{}

	if strings.Index(msg, queryMarker) == 0 {
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
