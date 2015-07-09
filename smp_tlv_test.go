package otr3

import (
	"testing"
)

const (
	tlvTypeLen  = 2
	tlvSizeLen  = 2
	mpiCountLen = 4
	lenOfRb     = 192
	lenOfCr     = 32
	lenOfD7     = 192
	g2aLen      = 192
	g3aLen      = 192
	c2len       = 32
	c3len       = 32
	d2len       = 192
	d3len       = 192
)

func Test_smpMessage1TLV(t *testing.T) {
	expectedLength := tlvTypeLen + tlvSizeLen + mpiCountLen + (4 + g2aLen) + (4 + c2len) + (4 + d2len) +
		(4 + g3aLen) + (4 + c3len) + (4 + d3len)

	exp := []byte{
		0x00, 0x02,
		0x03, 0x5C,
		0x00, 0x00, 0x00, 0x06,
		0x00, 0x00, 0x00, 0xC0,
		0x8A, 0x88, 0xC3, 0x45,
	}

	msg := fixtureMessage1()
	tlv := msg.tlv()
	assertEquals(t, len(tlv), expectedLength)
	assertDeepEquals(t, tlv[:len(exp)], exp)
}

func Test_smpMessage4TLV(t *testing.T) {
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
