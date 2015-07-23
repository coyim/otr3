package otr3

import (
	"crypto/aes"
	"testing"
)

func Test_tlvSerialize(t *testing.T) {
	expectedTLVBytes := []byte{0x00, 0x01, 0x00, 0x02, 0x01, 0x01}
	aTLV := tlv{
		tlvType:   0x0001,
		tlvLength: 0x0002,
		tlvValue:  []byte{0x01, 0x01},
	}
	aTLVBytes := aTLV.serialize()
	assertDeepEquals(t, aTLVBytes, expectedTLVBytes)
}

func Test_tlvDeserialize(t *testing.T) {
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

func Test_tlvDeserializeWithWrongType(t *testing.T) {
	aTLVBytes := []byte{0x00}
	aTLV := tlv{}
	err := aTLV.deserialize(aTLVBytes)
	assertEquals(t, err.Error(), "otr: wrong tlv type")
}

func Test_tlvDeserializeWithWrongLength(t *testing.T) {
	aTLVBytes := []byte{0x00, 0x01, 0x00}
	aTLV := tlv{}
	err := aTLV.deserialize(aTLVBytes)
	assertEquals(t, err.Error(), "otr: wrong tlv length")
}

func Test_tlvDeserializeWithWrongValue(t *testing.T) {
	aTLVBytes := []byte{0x00, 0x01, 0x00, 0x02, 0x01}
	aTLV := tlv{}
	err := aTLV.deserialize(aTLVBytes)
	assertEquals(t, err.Error(), "otr: wrong tlv value")
}

func Test_dataMsgPlainTextShouldDeserializeOneTLV(t *testing.T) {
	plain := []byte("helloworld")
	atlvBytes := []byte{0x00, 0x01, 0x00, 0x02, 0x01, 0x01}
	msg := append(plain, 0x00)
	msg = append(msg, atlvBytes...)
	aDataMsg := dataMsgPlainText{}
	err := aDataMsg.deserialize(msg)
	atlv := tlv{
		tlvType:   0x0001,
		tlvLength: 0x0002,
		tlvValue:  []byte{0x01, 0x01},
	}

	assertEquals(t, err, nil)
	assertDeepEquals(t, aDataMsg.plain, plain)
	assertDeepEquals(t, aDataMsg.tlvs[0], atlv)
}

func Test_dataMsgPlainTextShouldDeserializeMultiTLV(t *testing.T) {
	plain := []byte("helloworld")
	atlvBytes := []byte{0x00, 0x01, 0x00, 0x02, 0x01, 0x01}
	btlvBytes := []byte{0x00, 0x02, 0x00, 0x05, 0x01, 0x01, 0x01, 0x01, 0x01}
	msg := append(plain, 0x00)
	msg = append(msg, atlvBytes...)
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
	assertDeepEquals(t, aDataMsg.plain, plain)
	assertDeepEquals(t, aDataMsg.tlvs[0], atlv)
	assertDeepEquals(t, aDataMsg.tlvs[1], btlv)
}

func Test_dataMsgPlainTextShouldDeserializeNoTLV(t *testing.T) {
	plain := []byte("helloworld")
	aDataMsg := dataMsgPlainText{}
	err := aDataMsg.deserialize(plain)
	assertEquals(t, err, nil)
	assertDeepEquals(t, aDataMsg.plain, plain)
	assertDeepEquals(t, len(aDataMsg.tlvs), 0)
}

func Test_dataMsgPlainTextShouldSerialize(t *testing.T) {
	plain := []byte("helloworld")
	atlvBytes := []byte{0x00, 0x01, 0x00, 0x02, 0x01, 0x01}
	btlvBytes := []byte{0x00, 0x02, 0x00, 0x05, 0x01, 0x01, 0x01, 0x01, 0x01}
	msg := append(plain, 0x00)
	msg = append(msg, atlvBytes...)
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
	aDataMsg.plain = plain
	aDataMsg.tlvs = []tlv{atlv, btlv}

	assertDeepEquals(t, aDataMsg.serialize(), msg)
}

func Test_dataMsgPlainTextShouldSerializeWithoutTLVs(t *testing.T) {
	plain := []byte("helloworld")
	expected := append(plain, 0x00)

	dataMsg := dataMsgPlainText{
		plain: plain,
	}

	assertDeepEquals(t, dataMsg.serialize(), expected)
}

func Test_encrypt_EncryptsPlainMessageUsingSendingAESKeyAndCounter(t *testing.T) {
	plain := dataMsgPlainText{
		plain: []byte("we are awesome"),
	}

	var sendingAESKey [aes.BlockSize]byte
	copy(sendingAESKey[:], bytesFromHex("42e258bebf031acf442f52d6ef52d6f1"))
	expectedEncrypted := bytesFromHex("4f0de18011633ed0264ccc1840d64f")

	encrypted, err := plain.encrypt(sendingAESKey, [8]byte{})

	assertEquals(t, err, nil)
	assertDeepEquals(t, encrypted, expectedEncrypted)
}
