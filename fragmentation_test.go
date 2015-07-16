package otr3

import "testing"

const defaultInstanceTag = 0x00000100

func Test_isFragmented_returnsFalseForAShortValue(t *testing.T) {
	ctx := newContext(otrV2{}, nil)
	assertEquals(t, ctx.isFragmented([]byte("")), false)
}

func Test_isFragmented_returnsFalseForALongValue(t *testing.T) {
	ctx := newContext(otrV2{}, nil)
	assertEquals(t, ctx.isFragmented([]byte("?OTR:BLA")), false)
}

func Test_isFragmented_returnsFalseForAFragmentedV3MessageWhenRunningV2(t *testing.T) {
	ctx := newContext(otrV2{}, nil)
	assertEquals(t, ctx.isFragmented([]byte("?OTR|BLA")), false)
}

func Test_isFragmented_returnsTrueForAFragmentedV3MessageWhenRunningV3(t *testing.T) {
	ctx := newContext(otrV3{}, nil)
	assertEquals(t, ctx.isFragmented([]byte("?OTR|BLA")), true)
}

func Test_isFragmented_returnsTrueForAFragmentedV2MessageWhenRunningV2(t *testing.T) {
	ctx := newContext(otrV2{}, nil)
	assertEquals(t, ctx.isFragmented([]byte("?OTR,BLA")), true)
}

func Test_isFragmented_returnsTrueForAFragmentedV2MessageWhenRunningV3(t *testing.T) {
	ctx := newContext(otrV3{}, nil)
	assertEquals(t, ctx.isFragmented([]byte("?OTR,BLA")), true)
}

func Test_fragment_returnsNoChangeForASmallerPackage(t *testing.T) {
	ctx := newContext(otrV3{}, nil)

	data := []byte("one two three")

	assertDeepEquals(t, ctx.fragment(data, 13, defaultInstanceTag, defaultInstanceTag), [][]byte{data})
}

func Test_fragment_returnsFragmentsForNeededFragmentation(t *testing.T) {
	ctx := newContext(otrV3{}, nil)

	data := []byte("one two three")

	assertDeepEquals(t, ctx.fragment(data, 4, defaultInstanceTag, defaultInstanceTag+2), [][]byte{
		[]byte("?OTR|00000100|00000102,00001,00004,one "),
		[]byte("?OTR|00000100|00000102,00002,00004,two "),
		[]byte("?OTR|00000100|00000102,00003,00004,thre"),
		[]byte("?OTR|00000100|00000102,00004,00004,e"),
	})
}

func Test_fragment_returnsFragmentsForNeededFragmentationForV2(t *testing.T) {
	ctx := newContext(otrV2{}, nil)

	data := []byte("one two three")

	assertDeepEquals(t, ctx.fragment(data, 4, defaultInstanceTag, defaultInstanceTag+1), [][]byte{
		[]byte("?OTR,00001,00004,one "),
		[]byte("?OTR,00002,00004,two "),
		[]byte("?OTR,00003,00004,thre"),
		[]byte("?OTR,00004,00004,e"),
	})
}

// TODO: MINIMUM FRAGMENT SIZE
