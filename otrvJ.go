package otr3

import (
	"hash"

	"github.com/agl/ed25519"

	"golang.org/x/crypto/sha3"
)

type otrVJ struct {
	otrV3
}

func (v otrVJ) protocolVersion() string {
	return "J"
}

func (v otrVJ) protocolVersionNumber() uint16 {
	return 65074
}

func (v otrVJ) whitespaceTag() []byte {
	return convertToWhitespace(v.protocolVersion())
}

func (v otrVJ) hashInstance() hash.Hash {
	return sha3.New256()
}

func (v otrVJ) hash(val []byte) []byte {
	ret := sha3.Sum256(val)
	return ret[:]
}

func (v otrVJ) hashLength() int {
	return 32
}

func (v otrVJ) hash2Instance() hash.Hash {
	return sha3.New256()
}

func (v otrVJ) hash2(val []byte) []byte {
	ret := sha3.Sum256(val)
	return ret[:]
}

func (v otrVJ) hash2Length() int {
	return 32
}

func (v otrVJ) truncateLength() int {
	return 20
}

func (v otrVJ) keyLength() int {
	return ed25519.PublicKeySize
}
