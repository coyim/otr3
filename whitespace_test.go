package otr3

import "testing"

func Test_genWhitespace_forV2(t *testing.T) {
	hLen := len(whitespaceTagHeader)
	p := policies(allowV2)
	tag := genWhitespaceTag(p)

	assertDeepEquals(t, tag[:hLen], whitespaceTagHeader)
	assertDeepEquals(t, tag[hLen:], otrV2{}.whitespaceTag())
}

func Test_genWhitespace_forV3(t *testing.T) {
	hLen := len(whitespaceTagHeader)
	p := policies(allowV3)
	tag := genWhitespaceTag(p)

	assertDeepEquals(t, tag[:hLen], whitespaceTagHeader)
	assertDeepEquals(t, tag[hLen:], otrV3{}.whitespaceTag())
}

func Test_genWhitespace_forV2AndV3(t *testing.T) {
	hLen := len(whitespaceTagHeader)
	tLen := 8

	p := policies(allowV2 | allowV3)
	tag := genWhitespaceTag(p)

	assertDeepEquals(t, tag[:hLen], whitespaceTagHeader)
	assertDeepEquals(t, tag[hLen:hLen+tLen], otrV2{}.whitespaceTag())
	assertDeepEquals(t, tag[hLen+tLen:], otrV3{}.whitespaceTag())
}
