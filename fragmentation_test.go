package otr3

import (
	"crypto/rand"
	"testing"
)

const defaultInstanceTag = 0x00000100

func Test_isFragmented_returnsFalseForAShortValue(t *testing.T) {
	ctx := newConversation(otrV2{}, rand.Reader)
	assertEquals(t, ctx.version.isFragmented([]byte("")), false)
}

func Test_isFragmented_returnsFalseForALongValue(t *testing.T) {
	ctx := newConversation(otrV2{}, rand.Reader)
	assertEquals(t, ctx.version.isFragmented([]byte("?OTR:BLA")), false)
}

func Test_isFragmented_returnsFalseForAFragmentedV3MessageWhenRunningV2(t *testing.T) {
	ctx := newConversation(otrV2{}, rand.Reader)
	assertEquals(t, ctx.version.isFragmented([]byte("?OTR|BLA")), false)
}

func Test_isFragmented_returnsTrueForAFragmentedV3MessageWhenRunningV3(t *testing.T) {
	ctx := newConversation(otrV3{}, rand.Reader)
	assertEquals(t, ctx.version.isFragmented([]byte("?OTR|BLA")), true)
}

func Test_isFragmented_returnsTrueForAFragmentedV2MessageWhenRunningV2(t *testing.T) {
	ctx := newConversation(otrV2{}, rand.Reader)
	assertEquals(t, ctx.version.isFragmented([]byte("?OTR,BLA")), true)
}

func Test_isFragmented_returnsTrueForAFragmentedV2MessageWhenRunningV3(t *testing.T) {
	ctx := newConversation(otrV3{}, rand.Reader)
	assertEquals(t, ctx.version.isFragmented([]byte("?OTR,BLA")), true)
}

func Test_fragment_returnsNoChangeForASmallerPackage(t *testing.T) {
	ctx := newConversation(otrV3{}, rand.Reader)

	data := []byte("one two three")

	assertDeepEquals(t, ctx.fragment(data, 13, defaultInstanceTag, defaultInstanceTag), []ValidMessage{data})
}

func Test_fragment_returnsFragmentsForNeededFragmentation(t *testing.T) {
	ctx := newConversation(otrV3{}, rand.Reader)

	data := []byte("one two three")

	assertDeepEquals(t, ctx.fragment(data, 4, defaultInstanceTag, defaultInstanceTag+2), []ValidMessage{
		[]byte("?OTR|00000100|00000102,00001,00004,one ,"),
		[]byte("?OTR|00000100|00000102,00002,00004,two ,"),
		[]byte("?OTR|00000100|00000102,00003,00004,thre,"),
		[]byte("?OTR|00000100|00000102,00004,00004,e,"),
	})
}

func Test_fragment_returnsFragmentsForNeededFragmentationForV2(t *testing.T) {
	ctx := newConversation(otrV2{}, rand.Reader)

	data := []byte("one two three")

	assertDeepEquals(t, ctx.fragment(data, 4, defaultInstanceTag, defaultInstanceTag+1), []ValidMessage{
		[]byte("?OTR,00001,00004,one ,"),
		[]byte("?OTR,00002,00004,two ,"),
		[]byte("?OTR,00003,00004,thre,"),
		[]byte("?OTR,00004,00004,e,"),
	})
}

func Test_receiveFragment_returnsANewFragmentationContextForANewMessage(t *testing.T) {
	data := []byte("?OTR,00001,00004,one ,")

	fctx, e := receiveFragment(fragmentationContext{}, data)

	assertDeepEquals(t, fctx.frag, []byte("one "))
	assertDeepEquals(t, e, nil)
	assertEquals(t, fctx.currentIndex, uint16(1))
	assertEquals(t, fctx.currentLen, uint16(4))
}

func Test_receiveFragment_returnsTheSameContextIfMessageNumberIsZero(t *testing.T) {
	data := []byte("?OTR,00000,00004,one ,")
	fctx, _ := receiveFragment(fragmentationContext{}, data)
	assertDeepEquals(t, fctx, fragmentationContext{})
}

func Test_receiveFragment_returnsTheSameContextIfMessageCountIsZero(t *testing.T) {
	data := []byte("?OTR,00001,00000,one ,")
	fctx, _ := receiveFragment(fragmentationContext{}, data)
	assertDeepEquals(t, fctx, fragmentationContext{})
}

func Test_receiveFragment_returnsTheSameContextIfMessageNumberIsAboveMessageCount(t *testing.T) {
	data := []byte("?OTR,00005,00004,one ,")
	fctx, _ := receiveFragment(fragmentationContext{}, data)
	assertDeepEquals(t, fctx, fragmentationContext{})
}

func Test_receiveFragment_returnsTheNextContextIfMessageNumberIsOneMoreThanThePreviousOne(t *testing.T) {
	data := []byte("?OTR,00003,00004, one,")
	fctx, _ := receiveFragment(fragmentationContext{[]byte("blarg one two"), 2, 4}, data)
	assertDeepEquals(t, fctx, fragmentationContext{[]byte("blarg one two one"), 3, 4})
}

func Test_receiveFragment_resetsTheContextIfTheMessageCountIsNotTheSame(t *testing.T) {
	data := []byte("?OTR,00003,00005, one,")
	fctx, _ := receiveFragment(fragmentationContext{[]byte("blarg one two"), 2, 4}, data)
	assertDeepEquals(t, fctx, fragmentationContext{})
}

func Test_receiveFragment_resetsTheContextIfTheMessageNumberIsNotExactlyOnePlus(t *testing.T) {
	data := []byte("?OTR,00004,00005, one,")
	fctx, _ := receiveFragment(fragmentationContext{[]byte("blarg one two"), 2, 5}, data)
	assertDeepEquals(t, fctx, fragmentationContext{})
}

func Test_fragmentFinished_isFalseIfThereAreNoFragments(t *testing.T) {
	assertDeepEquals(t, fragmentsFinished(fragmentationContext{[]byte{}, 0, 0}), false)
}

func Test_fragmentFinished_isFalseIfTheNumberOfFragmentsIsNotTheSame(t *testing.T) {
	assertDeepEquals(t, fragmentsFinished(fragmentationContext{[]byte{}, 1, 2}), false)
}

func Test_fragmentFinished_isFalseIfTheNumberOfFragmentsIsNotTheSameWhereTheNumberIsHigher(t *testing.T) {
	assertDeepEquals(t, fragmentsFinished(fragmentationContext{[]byte{}, 3, 2}), false)
}

func Test_fragmentFinished_isTrueIfTheNumberIsTheSameAsTheCount(t *testing.T) {
	assertDeepEquals(t, fragmentsFinished(fragmentationContext{[]byte{}, 3, 3}), true)
}

func Test_parseFragment_returnsNotOKIfThereIsNotEnoughDataForThePrefix(t *testing.T) {
	_, _, _, ok := parseFragment([]byte{0x00, 0x00, 0x00, 0x00})
	assertDeepEquals(t, ok, false)
}

func Test_parseFragment_returnsNotOKIfThereAreNotEnoughParts(t *testing.T) {
	_, _, _, ok := parseFragment([]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x2C, 0x2C})
	assertDeepEquals(t, ok, false)
}

func Test_parseFragment_returnsNotOKIfThereAreTooManyParts(t *testing.T) {
	_, _, _, ok := parseFragment([]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x2C, 0x2C, 0x2C, 0x2C})
	assertDeepEquals(t, ok, false)
}

func Test_parseFragment_returnsNotOKIfTheIndexIsNotAValidUint(t *testing.T) {
	_, _, _, ok := parseFragment([]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x30, 0x30, 0x30, 0x30, 0x29, 0x2C, 0x30, 0x30, 0x30, 0x30, 0x31, 0x2C, 0x01, 0x2C})
	assertDeepEquals(t, ok, false)
}

func Test_parseFragment_returnsNotOKIfTheLengthIsNotAValidUint(t *testing.T) {
	_, _, _, ok := parseFragment([]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x30, 0x30, 0x30, 0x30, 0x31, 0x2C, 0x30, 0x30, 0x30, 0x30, 0x29, 0x2C, 0x01, 0x2C})
	assertDeepEquals(t, ok, false)
}

func Test_parseFragment_returnsOKIfThereAreExactlyTheRightAmountOfParts(t *testing.T) {
	_, _, _, ok := parseFragment([]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x30, 0x30, 0x30, 0x30, 0x31, 0x2C, 0x30, 0x30, 0x30, 0x30, 0x31, 0x2C, 0x01, 0x2C})
	assertDeepEquals(t, ok, true)
}

func Test_receiveFragment_returnsErrorIfTheFragmentIsNotCorrect(t *testing.T) {
	_, e := receiveFragment(fragmentationContext{}, []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x30, 0x30, 0x30, 0x30, 0x29, 0x2C, 0x30, 0x30, 0x30, 0x30, 0x31, 0x2C, 0x01, 0x2C})
	assertDeepEquals(t, e, newOtrError("invalid OTR fragment"))
}
