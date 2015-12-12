package otr3

import (
	"hash"

	"github.com/agl/ed25519"

	"golang.org/x/crypto/sha3"
)

var otrv3XFragmentationPrefix = []byte("?OTR^")

type otrV3X struct {
	otrV3
}

func (v otrV3X) protocolVersion() uint16 {
	return 4
}

func (v otrV3X) whitespaceTag() []byte {
	return []byte{
		0x20, 0x20, 0x09, 0x09, 0x20, 0x09, 0x09, 0x09,
	}
}

func (v otrV3X) hashInstance() hash.Hash {
	return sha3.New256()
}

func (v otrV3X) hash(val []byte) []byte {
	ret := sha3.Sum256(val)
	return ret[:]
}

func (v otrV3X) hashLength() int {
	return 32
}

func (v otrV3X) hash2Instance() hash.Hash {
	return sha3.New256()
}

func (v otrV3X) hash2(val []byte) []byte {
	ret := sha3.Sum256(val)
	return ret[:]
}

func (v otrV3X) hash2Length() int {
	return 32
}

func (v otrV3X) truncateLength() int {
	return 20
}

func (v otrV3X) keyLength() int {
	return ed25519.PublicKeySize
}
