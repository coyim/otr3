package otr3

import "bytes"

// fragmentationContext store the current fragmentation running. A fragmentationContext is zero-valid and can be immediately used without initialization.
// In order to follow the fragmentation rules, when the context needs to be reset, just create a new one - don't bother resetting variables
type fragmentationContext struct {
	frag                     []byte
	currentIndex, currentLen uint16
}

func min(l, r uint16) uint16 {
	if l < r {
		return l
	}
	return r
}

func fragmentStart(i, fraglen uint16) uint16 {
	return uint16(i * fraglen)
}

func fragmentEnd(i, fraglen, l uint16) uint16 {
	return uint16(min((i+1)*fraglen, l))
}

func fragmentData(data []byte, i int, fraglen, l uint16) []byte {
	return data[fragmentStart(uint16(i), fraglen):fragmentEnd(uint16(i), fraglen, l)]
}

func (c *conversation) fragment(data []byte, fraglen uint16, itags uint32, itagr uint32) [][]byte {
	var ret [][]byte
	len := len(data)

	if len <= int(fraglen) {
		ret = [][]byte{data}
	} else {
		numFragments := (len / int(fraglen)) + 1
		ret = make([][]byte, numFragments)
		for i := 0; i < numFragments; i++ {
			prefix := c.fragmentPrefix(i, numFragments, itags, itagr)
			ret[i] = append(append(prefix, fragmentData(data, i, fraglen, uint16(len))...), []byte(",")...)
		}
	}

	return ret
}

func receiveFragment(fctx fragmentationContext, data []byte) fragmentationContext {
	ret := fctx
	dataWithoutPrefix := data[5:]
	parts := bytes.Split(dataWithoutPrefix, []byte(",")) // this should always be safe, since the real data will always be base64 encoded
	ret.currentIndex, _ = bytesToUint16(parts[0])
	ret.currentLen, _ = bytesToUint16(parts[1])
	ret.frag = parts[2]
	return ret
}
