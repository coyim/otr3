package otr3

import (
	"bytes"
	"fmt"
	"math/big"
)

type otrV3 struct{}

func (v otrV3) parameterLength() int {
	return 192
}

func (v otrV3) isGroupElement(n *big.Int) bool {
	return isGroupElement(n)
}

var otrv3FragmentationPrefix = []byte("?OTR|")

func (v otrV3) isFragmented(data []byte) bool {
	return bytes.HasPrefix(data, otrv3FragmentationPrefix) || otrV2{}.isFragmented(data)
}

func (v otrV3) makeFragment(data []byte, n, total int, itags uint32, itagr uint32) []byte {
	return append([]byte(fmt.Sprintf("%s%x|%x,%05d,%05d,", string(otrv3FragmentationPrefix), itags, itagr, n+1, total)), data...)
}

func (v otrV3) versionNum() uint16 {
	return 3
}

func (v otrV3) needInstanceTag() bool {
	return true
}
