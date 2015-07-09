package otr3

import (
	"crypto/sha256"
	"hash"
	"math/big"
)

func appendWord(l []byte, r uint32) []byte {
	return append(l, byte(r>>24), byte(r>>16), byte(r>>8), byte(r))
}

func appendShort(l []byte, r uint16) []byte {
	return append(l, byte(r>>8), byte(r))
}

func appendData(l, r []byte) []byte {
	return append(appendWord(l, uint32(len(r))), r...)
}

func appendMPI(l []byte, r *big.Int) []byte {
	return appendData(l, r.Bytes())
}

func appendMPIs(l []byte, r ...*big.Int) []byte {
	for _, mpi := range r {
		l = appendMPI(l, mpi)
	}
	return l
}

func hashMPIs(h hash.Hash, magic byte, mpis ...*big.Int) []byte {
	if h != nil {
		h.Reset()
	} else {
		h = sha256.New()
	}

	h.Write([]byte{magic})
	for _, mpi := range mpis {
		h.Write(appendMPI(nil, mpi))
	}
	return h.Sum(nil)
}

func hashMPIsBN(h hash.Hash, magic byte, mpis ...*big.Int) *big.Int {
	return new(big.Int).SetBytes(hashMPIs(h, magic, mpis...))
}

func extractWord(d []byte, start int) uint32 {
	// TODO: errors
	return uint32(d[start])<<24 |
		uint32(d[start+1])<<16 |
		uint32(d[start+2])<<8 |
		uint32(d[start+3])
}

func extractMPI(d []byte, start int) (newIndex int, mpi *big.Int) {
	// TODO: errors
	mpiLen := int(extractWord(d, start))
	newIndex = start + 4 + mpiLen
	mpi = new(big.Int).SetBytes(d[start+4 : newIndex])
	return
}

func extractMPIs(d []byte, start int) []*big.Int {
	// TODO: errors
	mpiCount := int(extractWord(d, start))
	result := make([]*big.Int, mpiCount)
	current := start + 4
	for i := 0; i < mpiCount; i++ {
		current, result[i] = extractMPI(d, current)
	}
	return result
}

func extractShort(d []byte, start int) uint16 {
	// TODO: errors
	return uint16(d[start])<<8 |
		uint16(d[start+1])
}
