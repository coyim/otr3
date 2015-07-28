package otr3

var (
	whitespaceTagHeader = []byte{
		0x20, 0x09, 0x20, 0x20, 0x09, 0x09, 0x09, 0x09,
		0x20, 0x09, 0x20, 0x09, 0x20, 0x09, 0x20, 0x20,
	}
)

func genWhitespaceTag(p policies) []byte {
	ret := make([]byte, 16)

	copy(ret[:], whitespaceTagHeader)

	if p.has(allowV2) {
		ret = append(ret, otrV2{}.whitespaceTag()...)
	}

	if p.has(allowV3) {
		ret = append(ret, otrV3{}.whitespaceTag()...)
	}

	return ret
}