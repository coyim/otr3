package otr3

import (
	"math/big"
	"testing"
)

func Test_processDisconnectedTLV_forgetAllKeysAndTransitionToFinished(t *testing.T) {
	c := &Conversation{}
	c.msgState = encrypted
	c.keys.theirCurrentDHPubKey = big.NewInt(99)

	c.processDisconnectedTLV(tlv{}, dataMessageExtra{})

	assertEquals(t, c.msgState, finished)
	assertDeepEquals(t, c.keys, keyManagementContext{})
}

func Test_processDisconnectedTLV_signalsASecurityEvent(t *testing.T) {
	c := &Conversation{}
	c.msgState = encrypted
	c.keys.theirCurrentDHPubKey = big.NewInt(99)

	c.expectSecurityEvent(t, func() {
		c.processDisconnectedTLV(tlv{}, dataMessageExtra{})
	}, GoneInsecure)
}

func Test_processDisconnectedTLV_isActuallyInsecureWhenTheEventIsSignalled(t *testing.T) {
	c := &Conversation{}
	c.msgState = encrypted
	c.keys.theirCurrentDHPubKey = big.NewInt(99)

	c.securityEventHandler = dynamicSecurityEventHandler{func(event SecurityEvent) {
		assertEquals(t, c.msgState, finished)
	}}

	c.processDisconnectedTLV(tlv{}, dataMessageExtra{})
}

func Test_processDisconnectedTLV_doesntSignalsASecurityEventIfWeWereInPlaintext(t *testing.T) {
	c := &Conversation{}
	c.msgState = plainText
	c.keys.theirCurrentDHPubKey = big.NewInt(99)

	c.doesntExpectSecurityEvent(t, func() {
		c.processDisconnectedTLV(tlv{}, dataMessageExtra{})
	})
}

func Test_processDisconnectedTLV_doesntSignalsASecurityEventIfWeAreInFinished(t *testing.T) {
	c := &Conversation{}
	c.msgState = finished
	c.keys.theirCurrentDHPubKey = big.NewInt(99)

	c.doesntExpectSecurityEvent(t, func() {
		c.processDisconnectedTLV(tlv{}, dataMessageExtra{})
	})
}
