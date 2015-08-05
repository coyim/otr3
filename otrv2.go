package otr3

import (
	"bytes"
	"fmt"
	"math/big"
)

var otrv2FragmentationPrefix = []byte("?OTR,")

const otrv2HeaderLen = 3

type otrV2 struct{}

func (v otrV2) parameterLength() int {
	return 16
}

func (v otrV2) isGroupElement(n *big.Int) bool {
	return true
}

func (v otrV2) isFragmented(data []byte) bool {
	return bytes.HasPrefix(data, otrv2FragmentationPrefix)
}

func (v otrV2) parseFragmentPrefix(data []byte, itags uint32, itagr uint32) (rest []byte, ignore bool, ok bool) {
	if len(data) < 5 {
		return data, false, false
	}

	return data[5:], false, true
}

func (v otrV2) fragmentPrefix(n, total int, itags uint32, itagr uint32) []byte {
	return []byte(fmt.Sprintf("%s%05d,%05d,", string(otrv2FragmentationPrefix), n+1, total))
}

func (v otrV2) minFragmentSize() uint16 {
	return 18
}

func (v otrV2) protocolVersion() uint16 {
	return 2
}

func (v otrV2) whitespaceTag() []byte {
	return []byte{
		0x20, 0x20, 0x09, 0x09, 0x20, 0x20, 0x09, 0x20,
	}
}

func (v otrV2) messageHeader(c *Conversation, msgType byte) ([]byte, error) {
	out := appendShort(nil, v.protocolVersion())
	out = append(out, msgType)
	return out, nil
}

func (v otrV2) parseMessageHeader(c *Conversation, msg []byte) ([]byte, []byte, error) {
	if len(msg) < otrv2HeaderLen {
		return nil, nil, errInvalidOTRMessage
	}
	return msg[:otrv2HeaderLen], msg[otrv2HeaderLen:], nil
}
