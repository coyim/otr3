package otr3

import (
	"math/big"
	"testing"
)

func Test_processDisconnectedTLV_forgetAllKeysAndTransitionToFinished(t *testing.T) {
	c := newConversation(nil, nil)
	c.msgState = encrypted
	c.keys.theirCurrentDHPubKey = big.NewInt(99)

	c.processDisconnectedTLV(tlv{})

	assertEquals(t, c.msgState, finished)
	assertDeepEquals(t, c.keys, keyManagementContext{})
}
