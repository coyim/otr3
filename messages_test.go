package otr3

import (
	"crypto/aes"
	"crypto/sha1"
	"math/big"
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
	expectedEncrypted := bytesFromHex("4f0de18011633ed0264ccc1840d64f4cf8f0c91ef78890ab82edef36cb38210bb80760585ff43d736a9ff3e4bb05fc088fa34c2f21012988d539ebc839e9bc97633f4c42de15ea5c3c55a2b9940ca35015ded14205b9df78f936cb1521aedbea98df7dc03c116570ba8d034abc8e2d23185d2ce225845f38c08cb2aae192d66d601c1bc86149c98e8874705ae365b31cda76d274429de5e07b93f0ff29152716980a63c31b7bda150b222ba1d373f786d5f59f580d4f690a71d7fc620e0a3b05d692221ddeebac98d6ed16272e7c4596de27fb104ad747aa9a3ad9d3bc4f988af0beb21760df06047e267af0109baceb0f363bcaff7b205f2c42b3cb67a942f2")

	encrypted := plain.encrypt(sendingAESKey, [8]byte{})

	assertDeepEquals(t, encrypted, expectedEncrypted)
}

func Test_pad_PlainMessageUsingTLV0(t *testing.T) {
	plain := dataMsgPlainText{
		plain: []byte("123456"),
		tlvs: []tlv{
			smpMessageAbort{}.tlv(),
		},
	}

	paddedMessage := plain.pad()

	assertEquals(t, len(paddedMessage.tlvs), 2)
	assertEquals(t, paddedMessage.tlvs[1].tlvLength, uint16(245))
}

func Test_dataMsg_serializeWithAuthenticator(t *testing.T) {
	bodyLen := 30
	m := dataMsg{
		y:            big.NewInt(0x01),
		encryptedMsg: []byte{0x01},
	}.serialize()

	auth := sha1.Sum(m[:bodyLen])

	assertDeepEquals(t, m[bodyLen:bodyLen+len(auth)], auth[:])
}
