package otr3

import (
	"encoding/hex"
	"math/big"
	"testing"
)

var (
	x, y, r                   []byte
	expectedEncryptedGxValue  []byte
	expectedHashedGxValue     []byte
	expectedEncryptedSigValue []byte
	expectedMACSigValue       []byte
)

func init() {
	x, _ = hex.DecodeString("bbcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd")
	y, _ = hex.DecodeString("abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd")
	r, _ = hex.DecodeString("abcdabcdabcdabcdabcdabcdabcdabcd")
	expectedEncryptedGxValue, _ = hex.DecodeString("5dd6a5999be73a99b80bdb78194a125f3067bd79e69c648b76a068117a8c4d0f36f275305423a933541937145d85ab4618094cbafbe4db0c0081614c1ff0f516c3dc4f352e9c92f88e4883166f12324d82240a8f32874c3d6bc35acedb8d501aa0111937a4859f33aa9b43ec342d78c3a45a5939c1e58e6b4f02725c1922f3df8754d1e1ab7648f558e9043ad118e63603b3ba2d8cbfea99a481835e42e73e6cd6019840f4470b606e168b1cd4a1f401c3dc52525d79fa6b959a80d4e11f1ec3a7984cf9")
	expectedHashedGxValue, _ = hex.DecodeString("5265b02c1f43d43335e88ddcaf9f1e08e41011fc49e58f68f8d977f9d2a9cc52")

	expectedEncryptedSigValue, _ = hex.DecodeString("b15e9eb80f16f4beabcf7ac44c06f0b69b9f890a86a11b6cc2fd29e0f7cd15d9af7c052c4c55dfce929783e339ef094eedcfcaeb9edf896b7e201d46f16ba42dbec0a9738daa37c47a598849735b8b9ac8c98578431f8c7a6a54944ec6d830cb0ffcdf31d39cb8414bd3ddae0c483daf4e80a5990f7618edf648e68935126639d1752f49b2b8a83b170f39dd7d2a2c4ab99cb28684df2c6ee1feff9d171c25059eb6920bdf4cdab2fc0aed4aafeb66a51e938db8ca80881ad219413ecf7e0257")
	expectedMACSigValue, _ = hex.DecodeString("accccdbabdd7cd76a85d")
}

func TestDHCommitMessage(t *testing.T) {
	var ake AKE
	ake.protocolVersion = [2]byte{0x00, 0x03}
	ake.senderInstanceTag = 0x00000001
	ake.receiverInstanceTag = 0x00000001
	ake.Rand = fixedRand([]string{hex.EncodeToString(x[:]), hex.EncodeToString(r[:])})

	var out []byte
	out = appendBytes(out, ake.protocolVersion[:])
	out = append(out, msgTypeDHCommit)
	out = appendWord(out, ake.senderInstanceTag)
	out = appendWord(out, ake.receiverInstanceTag)
	out = appendBytes(out, expectedEncryptedGxValue)
	out = appendBytes(out, expectedHashedGxValue)

	result, err := ake.DHCommitMessage()
	assertEquals(t, err, nil)
	assertDeepEquals(t, result, out)
}

func TestDHKeyMessage(t *testing.T) {
	var ake AKE
	ake.protocolVersion = [2]byte{0x00, 0x03}
	ake.senderInstanceTag = 0x00000001
	ake.receiverInstanceTag = 0x00000001

	result := ake.DHKeyMessage()

	var out []byte
	out = appendBytes(out, ake.protocolVersion[:])
	out = append(out, msgTypeDHKey)
	out = appendWord(out, ake.senderInstanceTag)
	out = appendWord(out, ake.receiverInstanceTag)
	out = appendMPI(out, ake.gy)

	assertDeepEquals(t, result, out)
}

func TestRevealSigMessage(t *testing.T) {
	t.Skip("not finished")
	var ake AKE
	ake.protocolVersion = [2]byte{0x00, 0x03}
	ake.senderInstanceTag = 0x000000010
	ake.receiverInstanceTag = 0x00000001
	result := ake.RevealSigMessage()
	var out []byte
	out = appendBytes(out, ake.protocolVersion[:])
	out = append(out, msgTypeRevelSig)
	out = appendWord(out, ake.senderInstanceTag)
	out = appendWord(out, ake.receiverInstanceTag)
	out = appendBytes(out, ake.r[:])
	out = appendBytes(out, expectedEncryptedSigValue)
	out = appendBytes(out, expectedMACSigValue)
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

func Test_calcDHSharedSecret(t *testing.T) {
	var ake AKE
	tempgy, _ := hex.DecodeString("2cdacabb00e63d8949aa85f7e6a095b1ee81a60779e58f8938ff1a7ed1e651d954bd739162e699cc73b820728af53aae60a46d529620792ddf839c5d03d2d4e92137a535b27500e3b3d34d59d0cd460d1f386b5eb46a7404b15c1ef84840697d2d3d2405dcdda351014d24a8717f7b9c51f6c84de365fea634737ae18ba22253a8e15249d9beb2dded640c6c0d74e4f7e19161cf828ce3ffa9d425fb68c0fddcaa7cbe81a7a5c2c595cce69a255059d9e5c04b49fb15901c087e225da850ff27")
	ake.x = new(big.Int).SetBytes(x)
	ake.gy = new(big.Int).SetBytes(tempgy)

	encryptedSig := ake.calcDHSharedSecret()
	assertDeepEquals(t, encryptedSig, new(big.Int).SetBytes(expectedEncryptedSigValue))
}

func Test_calcAKEKeys(t *testing.T) {
	var ake AKE
	tempgy, _ := hex.DecodeString("2cdacabb00e63d8949aa85f7e6a095b1ee81a60779e58f8938ff1a7ed1e651d954bd739162e699cc73b820728af53aae60a46d529620792ddf839c5d03d2d4e92137a535b27500e3b3d34d59d0cd460d1f386b5eb46a7404b15c1ef84840697d2d3d2405dcdda351014d24a8717f7b9c51f6c84de365fea634737ae18ba22253a8e15249d9beb2dded640c6c0d74e4f7e19161cf828ce3ffa9d425fb68c0fddcaa7cbe81a7a5c2c595cce69a255059d9e5c04b49fb15901c087e225da850ff27")
	ake.x = new(big.Int).SetBytes(x)
	ake.gy = new(big.Int).SetBytes(tempgy)

	ake.calcDHSharedSecret()
	ake.calcAKEKeys()
	assertEquals(t, hex.EncodeToString(ake.ssid[:]), "9cee5d2c7edbc86d")
	assertEquals(t, hex.EncodeToString(ake.revealKey.c[:]), "5745340b350364a02a0ac1467a318dcc")
	assertEquals(t, hex.EncodeToString(ake.sigKey.c[:]), "d942cc80b66503414c05e3752d9ba5c4")
	assertEquals(t, hex.EncodeToString(ake.revealKey.m1[:]), "d3251498fb9d977d07392a96eafb8c048d6bc67064bd7da72aa38f20f87a2e3d")
	assertEquals(t, hex.EncodeToString(ake.revealKey.m2[:]), "79c101a78a6c5819547a36b4813c84a8ac553d27a5d4b58be45dd0f3a67d3ca6")
	assertEquals(t, hex.EncodeToString(ake.sigKey.m1[:]), "b6254b8eab0ad98152949454d23c8c9b08e4e9cf423b27edc09b1975a76eb59c")
	assertEquals(t, hex.EncodeToString(ake.sigKey.m2[:]), "954be27015eeb0455250144d906e83e7d329c49581aea634c4189a3c981184f5")
}
