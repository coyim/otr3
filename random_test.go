package otr3

import (
	"crypto/rand"
	"testing"
)

func Test_conversation_rand_returnsTheSetRandomIfThereIsOne(t *testing.T) {
	r := fixtureRand()
	c := newConversation(otrV3{}, r)
	assertEquals(t, c.rand(), r)
}

func Test_conversation_rand_returnsRandReaderIfNoRandomnessIsSet(t *testing.T) {
	c := newConversation(otrV3{}, nil)
	assertEquals(t, c.rand(), rand.Reader)
}
