package otr3

import "math/big"

type otrV2 struct{}

func (v otrV2) parameterLength() int {
	return 16
}

func (v otrV2) isGroupElement(n *big.Int) bool {
	return true
}

func (v otrV2) Int() uint16 {
	return 2
}
