package otr3

import "testing"

func Test_tlvDeserilze(t *testing.T) {
	aTLVBytes := []byte{0x00, 0x01, 0x00, 0x02, 0x01, 0x01}
	aTLV := tlv{}
	expectedTLV := tlv{
		tlvType:   0x0001,
		tlvLength: 0x0002,
		tlvValue:  []byte{0x01, 0x01},
	}
	err := aTLV.deserialize(aTLVBytes)
	assertEquals(t, err, nil)
	assertDeepEquals(t, aTLV, expectedTLV)
}

func Test_tlvDeserilzeWithWrongType(t *testing.T) {
	aTLVBytes := []byte{0x00}
	aTLV := tlv{}
	err := aTLV.deserialize(aTLVBytes)
	assertEquals(t, err.Error(), "otr: wrong tlv type")
}

func Test_tlvDeserilzeWithWrongLength(t *testing.T) {
	aTLVBytes := []byte{0x00, 0x01, 0x00}
	aTLV := tlv{}
	err := aTLV.deserialize(aTLVBytes)
	assertEquals(t, err.Error(), "otr: wrong tlv length")
}

func Test_tlvDeserilzeWithWrongValue(t *testing.T) {
	aTLVBytes := []byte{0x00, 0x01, 0x00, 0x02, 0x01}
	aTLV := tlv{}
	err := aTLV.deserialize(aTLVBytes)
	assertEquals(t, err.Error(), "otr: wrong tlv value")
}

func Test_dataMsgShouldDeserializeOneTLV(t *testing.T) {
	nul := []byte{0x00}
	atlvBytes := []byte{0x00, 0x01, 0x00, 0x02, 0x01, 0x01}
	msg := append(nul, atlvBytes...)
	aDataMsg := dataMsgPlainText{}
	err := aDataMsg.deserialize(msg)
	atlv := tlv{
		tlvType:   0x0001,
		tlvLength: 0x0002,
		tlvValue:  []byte{0x01, 0x01},
	}

	assertEquals(t, err, nil)
	assertDeepEquals(t, aDataMsg.tlvs[0].tlvType, atlv.tlvType)
	assertDeepEquals(t, aDataMsg.tlvs[0].tlvLength, atlv.tlvLength)
	assertDeepEquals(t, aDataMsg.tlvs[0].tlvValue, atlv.tlvValue)
}

func Test_dataMsgShouldDeserializeMultiTLV(t *testing.T) {
	nul := []byte{0x00}
	atlvBytes := []byte{0x00, 0x01, 0x00, 0x02, 0x01, 0x01}
	btlvBytes := []byte{0x00, 0x02, 0x00, 0x05, 0x01, 0x01, 0x01, 0x01, 0x01}
	msg := append(nul, atlvBytes...)
	msg = append(msg, btlvBytes...)
	aDataMsg := dataMsgPlainText{}
	err := aDataMsg.deserialize(msg)
	atlv := tlv{
		tlvType:   0x0001,
		tlvLength: 0x0002,
		tlvValue:  []byte{0x01, 0x01},
	}

	btlv := tlv{
		tlvType:   0x0002,
		tlvLength: 0x0005,
		tlvValue:  []byte{0x01, 0x01, 0x01, 0x01, 0x01},
	}

	assertEquals(t, err, nil)
	assertEquals(t, aDataMsg.nul, byte(0x00))
	assertDeepEquals(t, aDataMsg.tlvs[0], atlv)
	assertDeepEquals(t, aDataMsg.tlvs[1], btlv)
}

func Test_dataMsgShouldDeserializeWithErrorWhenFirstByteNotEquals0x00(t *testing.T) {
	msg := []byte{0x01}
	aDataMsg := dataMsgPlainText{}
	err := aDataMsg.deserialize(msg)

	assertEquals(t, err.Error(), "otr: corrupt data message")
}

func Test_dataMsgShouldSerialize(t *testing.T) {
	nul := []byte{0x00}
	atlvBytes := []byte{0x00, 0x01, 0x00, 0x02, 0x01, 0x01}
	btlvBytes := []byte{0x00, 0x02, 0x00, 0x05, 0x01, 0x01, 0x01, 0x01, 0x01}
	msg := append(nul, atlvBytes...)
	msg = append(msg, btlvBytes...)
	aDataMsg := dataMsgPlainText{}
	atlv := tlv{
		tlvType:   0x0001,
		tlvLength: 0x0002,
		tlvValue:  []byte{0x01, 0x01},
	}

	btlv := tlv{
		tlvType:   0x0002,
		tlvLength: 0x0005,
		tlvValue:  []byte{0x01, 0x01, 0x01, 0x01, 0x01},
	}
	aDataMsg.nul = 0x00
	aDataMsg.tlvs = []tlv{atlv, btlv}

	assertDeepEquals(t, aDataMsg.serialize(), msg)
}
