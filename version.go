package otr3

import "math/big"

type otrVersion interface {
	protocolVersion() uint16
	parameterLength() int
	isGroupElement(n *big.Int) bool
	isFragmented(data []byte) bool
	fragmentPrefix(n, total int, itags uint32, itagr uint32) []byte
	needInstanceTag() bool
	headerLen() int
	whitespaceTag() []byte
}

func newOtrVersion(v uint16) (otrVersion, error) {
	switch v {
	case 2:
		return otrV2{}, nil
	case 3:
		return otrV3{}, nil
	}

	return nil, errInvalidVersion
}
