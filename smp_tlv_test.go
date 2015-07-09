package otr3

import (
	"testing"
)

const (
	tlvTypeLen  = 2
	tlvSizeLen  = 2
	mpiCountLen = 4
	c2Len       = 32
	c3Len       = 32
	cpLen       = 32
	crLen       = 32
	d2Len       = 192
	d3Len       = 192
	d5Len       = 192
	d6Len       = 192
	d7Len       = 192
	g2aLen      = 192
	g2bLen      = 192
	g3aLen      = 192
	g3bLen      = 192
	pbLen       = 192
	qbLen       = 192
	rbLen       = 192
)

func Test_smpMessage1TLV(t *testing.T) {
	expectedLength := tlvTypeLen + tlvSizeLen + mpiCountLen + (4 + g2aLen) + (4 + c2Len) + (4 + d2Len) +
		(4 + g3aLen) + (4 + c3Len) + (4 + d3Len)

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

func Test_smpMessage2TLV(t *testing.T) {
	expectedLength := tlvTypeLen + tlvSizeLen + mpiCountLen +
		(4 + g2bLen) + (4 + c2Len) + (4 + d2Len) + (4 + g3bLen) +
		(4 + c3Len) + (4 + d3Len) + (4 + pbLen) + (4 + qbLen) +
		(4 + cpLen) + (4 + d5Len) + (4 + d6Len)

	exp := []byte{
		0x00, 0x03,
		0x06, 0x90,
		0x00, 0x00, 0x00, 0x0b,
		0x00, 0x00, 0x00, 0xC0,
		0x8A, 0x88, 0xC3, 0x45,
	}

	msg := fixtureMessage2()
	tlv := msg.tlv()
	assertEquals(t, len(tlv), expectedLength)
	assertDeepEquals(t, tlv[:len(exp)], exp)
}

func Test_smpMessage4TLV(t *testing.T) {
	expectedLength := tlvTypeLen + tlvSizeLen + mpiCountLen + (4 + rbLen) + (4 + crLen) + (4 + d7Len)
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
