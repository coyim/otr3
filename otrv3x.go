package otr3

import (
	"bytes"
	"fmt"
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

func (v otrV3X) isFragmented(data []byte) bool {
	return bytes.HasPrefix(data, otrv3XFragmentationPrefix) || otrV3{}.isFragmented(data)
}

func (v otrV3X) parseFragmentPrefix(c *Conversation, data []byte) (rest []byte, ignore bool, ok bool) {
	if len(data) < 23 {
		return data, false, false
	}

	header := data[:23]
	headerPart := bytes.Split(bytes.Split(header, fragment3XSeparator)[1], fragmentSeparator)[0]
	itagParts := bytes.Split(headerPart, fragmentItagsSeparator)

	if len(itagParts) < 2 {
		return data, false, false
	}

	senderInstanceTag, err1 := parseItag(itagParts[0])
	if err1 != nil {
		return data, false, false
	}

	receiverInstanceTag, err2 := parseItag(itagParts[1])
	if err2 != nil {
		return data, false, false
	}

	if err := v.verifyInstanceTags(c, senderInstanceTag, receiverInstanceTag); err != nil {
		switch err {
		case errInvalidOTRMessage:
			return data, false, false
		case errReceivedMessageForOtherInstance:
			return data, true, true
		}
	}

	return data[23:], false, true
}

func (v otrV3X) fragmentPrefix(n, total int, itags uint32, itagr uint32) []byte {
	return []byte(fmt.Sprintf("%s%08x|%08x,%05d,%05d,", string(otrv3XFragmentationPrefix), itags, itagr, n+1, total))
}

func (v otrV3X) whitespaceTag() []byte {
	return convertToWhitespace("4")
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
