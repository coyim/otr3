package otr3

import "bytes"

var (
	fragmentSeparator = []byte{','}
)

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
	len := len(data)

	if len <= int(fraglen) {
		return [][]byte{data}
	}

	numFragments := (len / int(fraglen)) + 1
	ret := make([][]byte, numFragments)
	for i := 0; i < numFragments; i++ {
		prefix := c.fragmentPrefix(i, numFragments, itags, itagr)
		ret[i] = append(append(prefix, fragmentData(data, i, fraglen, uint16(len))...), fragmentSeparator[0])
	}
	return ret
}

func fragmentsFinished(fctx fragmentationContext) bool {
	return fctx.currentIndex > 0 && fctx.currentIndex == fctx.currentLen
}

func parseFragment(data []byte) (resultData []byte, ix uint16, length uint16) {
	dataWithoutPrefix := data[5:]
	parts := bytes.Split(dataWithoutPrefix, fragmentSeparator) // this should always be safe, since the real data will always be base64 encoded
	ix, _ = bytesToUint16(parts[0])
	length, _ = bytesToUint16(parts[1])
	resultData = parts[2]
	return
}

func fragmentIsInvalid(ix, l uint16) bool {
	return ix == 0 || l == 0 || ix > l
}

func fragmentIsFirstMessage(ix, l uint16) bool {
	return ix == 1
}

func fragmentIsNextMessage(beforeCtx fragmentationContext, ix, l uint16) bool {
	return beforeCtx.currentIndex+1 == ix && beforeCtx.currentLen == l
}

func (ctx fragmentationContext) discardFragment() fragmentationContext {
	return ctx
}

func (ctx fragmentationContext) appendFragment(data []byte, ix, l uint16) fragmentationContext {
	return fragmentationContext{append(ctx.frag, data...), ix, l}
}

func restartFragment(data []byte, ix, l uint16) fragmentationContext {
	return fragmentationContext{data, ix, l}
}

func forgetFragment() fragmentationContext {
	return fragmentationContext{}
}

func receiveFragment(beforeCtx fragmentationContext, data []byte) fragmentationContext {
	// TODO: check instance tags, and optionally warn the user
	// TODO: check for malformed data

	resultData, ix, l := parseFragment(data)

	switch {
	case fragmentIsInvalid(ix, l):
		return beforeCtx.discardFragment()
	case fragmentIsFirstMessage(ix, l):
		return restartFragment(resultData, ix, l)
	case fragmentIsNextMessage(beforeCtx, ix, l):
		return beforeCtx.appendFragment(resultData, ix, l)
	default:
		return forgetFragment()
	}

}
