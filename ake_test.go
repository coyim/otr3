package otr3

import (
	"encoding/hex"
	"testing"
)

var r = [16]byte{
	0x00, 0x01, 0x02, 0x03,
	0x00, 0x01, 0x02, 0x03,
	0x00, 0x01, 0x02, 0x03,
	0x00, 0x01, 0x02, 0x03,
}
var x = [40]byte{
	0x00, 0x01, 0x02, 0x03,
	0x00, 0x01, 0x02, 0x03,
	0x00, 0x01, 0x02, 0x03,
	0x00, 0x01, 0x02, 0x03,
	0x00, 0x01, 0x02, 0x03,
	0x00, 0x01, 0x02, 0x03,
	0x00, 0x01, 0x02, 0x03,
	0x00, 0x01, 0x02, 0x03,
	0x00, 0x01, 0x02, 0x03,
	0x00, 0x01, 0x02, 0x03,
}
var expectedEncryptedGxValue []byte
var expectedHashedGxValue []byte

func init() {
	expectedEncryptedGxValue, _ = hex.DecodeString("d032246eaa0c13e844874f8b6f31259ea0d17c1c6a54b6a3578a0318e956544146aad8a25bcf3fa29207902e40b51d5de0bbfc099c9ed52d09e46bfce785a66c969f0a9ed02d6e4b3a9f2c85c9f750abb53af13f381557717159fcf5d53bde1119e77ee6ec2de8748936d2a906eb73de943443600a77a8ec6f2994be35a0c2439fb767331f752d342ec27830dd63f9ef7e4d96ee66ffea8aba7aae664107a5af3d7124a8d37c238a228e1276d21af8af1f4f7363f25fcb8e9b7bd072c51db8a2457b5d3e")
	expectedHashedGxValue, _ = hex.DecodeString("d0a4c6efc6fd45398e67fc9166c2097b801727a19c47a7700437abad3e9eaebf")
}

func TestDHCommitMessage(t *testing.T) {
	var ake AKE
	ake.protocolVersion = [2]byte{0x00, 0x03}
	ake.sendInstag = 0x00000001
	ake.receiveInstag = 0x00000001
	ake.Rand = fixedRand([]string{hex.EncodeToString(x[:]), hex.EncodeToString(r[:]), hex.EncodeToString(r[:])})

	var out []byte
	out = appendBytes(out, ake.protocolVersion[:])
	out = append(out, msgTypeDHCommit)
	out = appendWord(out, ake.sendInstag)
	out = appendWord(out, ake.receiveInstag)
	out = appendBytes(out, expectedEncryptedGxValue)
	out = appendBytes(out, expectedHashedGxValue)

	result, err := ake.DHCommitMessage()
	assertEquals(t, err, nil)
	assertDeepEquals(t, result, out)
}

func TestDHKeyMessage(t *testing.T) {
	var ake AKE
	ake.protocolVersion = [2]byte{0x00, 0x03}
	ake.sendInstag = 0x00000001
	ake.receiveInstag = 0x00000001

	result := ake.DHKeyMessage()

	var out []byte
	out = appendBytes(out, ake.protocolVersion[:])
	out = append(out, msgTypeDHKey)
	out = appendWord(out, ake.sendInstag)
	out = appendWord(out, ake.receiveInstag)
	out = appendMPI(out, ake.gy)

	assertDeepEquals(t, result, out)
}

func Test_encryptedGx(t *testing.T) {
	var ake AKE
	ake.Rand = fixedRand([]string{hex.EncodeToString(x[:]), hex.EncodeToString(r[:])})
	ake.initGx()

	encryptGx, err := ake.encryptedGx()
	assertEquals(t, err, nil)
	assertEquals(t, len(encryptGx), len(appendMPI([]byte{}, ake.gx)))
}

func Test_hashedGx(t *testing.T) {
	var ake AKE
	ake.Rand = fixedRand([]string{hex.EncodeToString(x[:])})
	ake.initGx()
	hashedGx := ake.hashedGx()
	assertDeepEquals(t, hashedGx, expectedHashedGxValue)
}
