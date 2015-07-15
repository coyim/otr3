package otr3

import (
	"bytes"
	"fmt"
	"math/big"
)

type otrV2 struct{}

func (v otrV2) parameterLength() int {
	return 16
}

func (v otrV2) isGroupElement(n *big.Int) bool {
	return true
}

var otrv2FragmentationPrefix = []byte("?OTR,")

func (v otrV2) isFragmented(data []byte) bool {
	return bytes.HasPrefix(data, otrv2FragmentationPrefix)
}

func (v otrV2) makeFragment(data []byte, n, total int, itags uint32, itagr uint32) []byte {
	return append([]byte(fmt.Sprintf("%s%05d,%05d,", string(otrv2FragmentationPrefix), n+1, total)), data...)
}

func (v otrV2) protocolVersion() uint16 {
	return 2
}

func (v otrV2) needInstanceTag() bool {
	return false
}
