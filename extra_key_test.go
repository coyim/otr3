package otr3

import "testing"

func Test_processExtraSymmetricKeyTLV_signalsAReceivedKeyEventWithTheExtraKey(t *testing.T) {
	c := &Conversation{}
	extraKey := []byte{0x89, 0x11, 0x13, 0x66, 0xAB, 0xCD}
	x := dataMessageExtra{extraKey}

	called := false

	c.receivedKeyHandler = dynamicReceivedKeyHandler{func(usage uint32, usageData []byte, symkey []byte) {
		assertDeepEquals(t, symkey, extraKey)
		called = true
	}}

	c.processExtraSymmetricKeyTLV(tlv{tlvTypeExtraSymmetricKey, 0x04, []byte{0xAB, 0x12, 0xCD, 0x44}}, x)

	assertEquals(t, called, true)
}

func Test_processExtraSymmetricKeyTLV_signalsTheReceivedUsageData(t *testing.T) {
	c := &Conversation{}
	extraKey := []byte{0x89, 0x11, 0x13, 0x66, 0xAB, 0xCD}
	x := dataMessageExtra{extraKey}

	called := false

	c.receivedKeyHandler = dynamicReceivedKeyHandler{func(usage uint32, usageData []byte, symkey []byte) {
		assertEquals(t, usage, uint32(0xAB12CD44))
		called = true
	}}

	c.processExtraSymmetricKeyTLV(tlv{tlvTypeExtraSymmetricKey, 0x04, []byte{0xAB, 0x12, 0xCD, 0x44}}, x)

	assertEquals(t, called, true)
}

func Test_processExtraSymmetricKeyTLV_doesntSignalAnythingIfThereIsNoUsageData(t *testing.T) {
	c := &Conversation{}
	extraKey := []byte{0x89, 0x11, 0x13, 0x66, 0xAB, 0xCD}
	x := dataMessageExtra{extraKey}

	c.receivedKeyHandler = dynamicReceivedKeyHandler{func(usage uint32, usageData []byte, symkey []byte) {
		t.Errorf("Didn't expect a received key event one")
	}}

	c.processExtraSymmetricKeyTLV(tlv{tlvTypeExtraSymmetricKey, 0x00, []byte{}}, x)
}

func Test_processExtraSymmetricKeyTLV_providesExtraUsageDataIfGiven(t *testing.T) {
	c := &Conversation{}
	extraKey := []byte{0x89, 0x11, 0x13, 0x66, 0xAB, 0xCD}
	x := dataMessageExtra{extraKey}

	called := false

	c.receivedKeyHandler = dynamicReceivedKeyHandler{func(usage uint32, usageData []byte, symkey []byte) {
		assertDeepEquals(t, usageData, []byte{0x01, 0x02})
		called = true
	}}

	c.processExtraSymmetricKeyTLV(tlv{tlvTypeExtraSymmetricKey, 0x06, []byte{0xAB, 0x12, 0xCD, 0x44, 0x01, 0x02, 0x04}}, x)

	assertEquals(t, called, true)
}

func Test_processExtraSymmetricKeyTLV_alwaysReturnsNilAndNil(t *testing.T) {
	c := &Conversation{}
	x := dataMessageExtra{[]byte{0x89, 0x11, 0x13, 0x66, 0xAB, 0xCD}}

	c.receivedKeyHandler = dynamicReceivedKeyHandler{func(usage uint32, usageData []byte, symkey []byte) {
	}}

	res, err := c.processExtraSymmetricKeyTLV(tlv{tlvTypeExtraSymmetricKey, 0x06, []byte{0xAB, 0x12, 0xCD, 0x44, 0x01, 0x02, 0x04}}, x)

	assertNil(t, res)
	assertNil(t, err)
}
