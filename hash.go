package otr3

import (
	"crypto/sha1"
	"hash"

	"golang.org/x/crypto/sha3"
)

func fingerprintHashInstanceForVersion(v int) hash.Hash {
	switch v {
	case 2, 3:
		return sha1.New()
	case 4:
		return sha3.New256()
	}

	return nil
}
