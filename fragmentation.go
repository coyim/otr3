package otr3

func min(l, r int) int {
	if l < r {
		return l
	}
	return r
}

func (c *context) fragment(data []byte, fraglen int, itags uint32, itagr uint32) [][]byte {
	var ret [][]byte
	len := len(data)

	if len <= fraglen {
		ret = [][]byte{data}
	} else {
		numFragments := (len / fraglen) + 1
		ret = make([][]byte, numFragments)
		for i := 0; i < numFragments; i++ {
			ret[i] = c.makeFragment(data[(i*fraglen):min(((i+1)*fraglen), len)], i, numFragments, itags, itagr)
		}
	}

	return ret
}
