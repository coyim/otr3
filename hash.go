package otr3

import (
	"crypto/sha1"
	"hash"

	"golang.org/x/crypto/sha3"
)

func fingerprintHashInstanceForVersion(v uint16) hash.Hash {
	switch v {
	case otrV2{}.protocolVersionNumber(), otrV3{}.protocolVersionNumber():
		return sha1.New()
	case otrVJ{}.protocolVersionNumber():
		return sha3.New256()
	}

	return nil
}
