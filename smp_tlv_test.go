package otr3

import (
	"testing"
)

func Test_smpMessage4TLV(t *testing.T) {
	tlvTypeLen := 2
	tlvSizeLen := 2
	mpiCountLen := 4
	lenOfRb := 192
	lenOfCr := 32
	lenOfD7 := 192
	expectedLength := tlvTypeLen + tlvSizeLen + mpiCountLen + (4 + lenOfRb) + (4 + lenOfCr) + (4 + lenOfD7)
	exp := []byte{
		0x00, 0x05,
		0x01, 0xB0,
		0x00, 0x00, 0x00, 0x03,
		0x00, 0x00, 0x00, 0xC0,
		0x6C, 0xA8, 0x8E, 0xE8,
	}

	msg := fixtureMessage4()
	tlv := msg.tlv()
	assertEquals(t, len(tlv), expectedLength)
	assertDeepEquals(t, tlv[:len(exp)], exp)
}
