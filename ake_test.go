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
	out = appendData(out, ake.protocolVersion[:])
	out = append(out, msgTypeDHCommit)
	out = appendWord(out, ake.senderInstanceTag)
	out = appendWord(out, ake.receiverInstanceTag)
	out = appendData(out, expectedEncryptedGxValue)
	out = appendData(out, expectedHashedGxValue)

	result, err := ake.DHCommitMessage()
	assertEquals(t, err, nil)
	assertDeepEquals(t, result, out)
}

func TestDHKeyMessage(t *testing.T) {
	var ake AKE
	ake.protocolVersion = [2]byte{0x00, 0x03}
	ake.senderInstanceTag = 0x00000001
	ake.receiverInstanceTag = 0x00000001

	result, _ := ake.DHKeyMessage()

	var out []byte
	out = appendData(out, ake.protocolVersion[:])
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
	out = appendData(out, ake.protocolVersion[:])
	out = append(out, msgTypeRevealSig)
	out = appendWord(out, ake.senderInstanceTag)
	out = appendWord(out, ake.receiverInstanceTag)
	out = appendData(out, ake.r[:])
	out = appendData(out, expectedEncryptedSigValue)
	out = appendData(out, expectedMACSigValue)
	assertDeepEquals(t, result, out)
}

func Test_encryptedGx(t *testing.T) {
	var ake AKE
	ake.Rand = fixedRand([]string{hex.EncodeToString(x[:]), hex.EncodeToString(r[:])})
	ake.gx, _ = new(big.Int).SetString("75dfab5a1eab059052d0ad881c4938d52669630d61833a367155d67d03a457f619683d0fa829781e974fd24f6865e8128a9312a167b77326a87dea032fc31784d05b18b9cbafebe162ae9b5369f8b0c5911cf1be757f45f2a674be5126a714a6366c28086b3c7088911dcc4e5fb1481ad70a5237b8e4a6aff4954c2ca6df338b9f08691e4c0defe12689b37d4df30ddef2687f789fcf623c5d0cf6f09b7e5e69f481d5fd1b24a77636fb676e6d733d129eb93e81189340233044766a36eb07d", 16)
	encryptGx, err := ake.encryptedGx()
	assertEquals(t, err, nil)
	assertEquals(t, len(encryptGx), len(appendMPI([]byte{}, ake.gx)))
}

func Test_hashedGx(t *testing.T) {
	var ake AKE
	ake.Rand = fixedRand([]string{hex.EncodeToString(x[:])})
	ake.gx, _ = new(big.Int).SetString("75dfab5a1eab059052d0ad881c4938d52669630d61833a367155d67d03a457f619683d0fa829781e974fd24f6865e8128a9312a167b77326a87dea032fc31784d05b18b9cbafebe162ae9b5369f8b0c5911cf1be757f45f2a674be5126a714a6366c28086b3c7088911dcc4e5fb1481ad70a5237b8e4a6aff4954c2ca6df338b9f08691e4c0defe12689b37d4df30ddef2687f789fcf623c5d0cf6f09b7e5e69f481d5fd1b24a77636fb676e6d733d129eb93e81189340233044766a36eb07d", 16)
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

func Test_generateEncryptedSignature(t *testing.T) {
	var ake AKE
	tempgx, _ := hex.DecodeString("75dfab5a1eab059052d0ad881c4938d52669630d61833a367155d67d03a457f619683d0fa829781e974fd24f6865e8128a9312a167b77326a87dea032fc31784d05b18b9cbafebe162ae9b5369f8b0c5911cf1be757f45f2a674be5126a714a6366c28086b3c7088911dcc4e5fb1481ad70a5237b8e4a6aff4954c2ca6df338b9f08691e4c0defe12689b37d4df30ddef2687f789fcf623c5d0cf6f09b7e5e69f481d5fd1b24a77636fb676e6d733d129eb93e81189340233044766a36eb07d")
	tempgy, _ := hex.DecodeString("2cdacabb00e63d8949aa85f7e6a095b1ee81a60779e58f8938ff1a7ed1e651d954bd739162e699cc73b820728af53aae60a46d529620792ddf839c5d03d2d4e92137a535b27500e3b3d34d59d0cd460d1f386b5eb46a7404b15c1ef84840697d2d3d2405dcdda351014d24a8717f7b9c51f6c84de365fea634737ae18ba22253a8e15249d9beb2dded640c6c0d74e4f7e19161cf828ce3ffa9d425fb68c0fddcaa7cbe81a7a5c2c595cce69a255059d9e5c04b49fb15901c087e225da850ff27")
	ake.x = new(big.Int).SetBytes(x)
	ake.gx = new(big.Int).SetBytes(tempgx)
	ake.gy = new(big.Int).SetBytes(tempgy)
	ake.myKeyId = 1

	ake.calcDHSharedSecret()
	ake.calcAKEKeys()
	expectedEncryptedSignature, _ := hex.DecodeString("000001d2dda2d4ef365711c172dad92804b201fcd2fdd6444568ebf0844019fb65ca4f5f57031936f9a339e08bfd4410905ab86c5d6f73e6c94de6a207f373beff3f7676faee7b1d3be21e630fe42e95db9d4ac559252bff530481301b590e2163b99bde8aa1b07448bf7252588e317b0ba2fc52f85a72a921ba757785b949e5e682341d98800aa180aa0bd01f51180d48260e4358ffae72a97f652f02eb6ae3bc6a25a317d0ca5ed0164a992240baac8e043f848332d22c10a46d12c745dc7b1b0ee37fd14614d4b69d500b8ce562040e3a4bfdd1074e2312d3e3e4c68bd15d70166855d8141f695b21c98c6055a5edb9a233925cf492218342450b806e58b3a821e5d1d2b9c6b9cbcba263908d7190a3428ace92572c064a328f86fa5b8ad2a9c76d5b9dcaeae5327f545b973795f7c655248141c2f82db0a2045e95c1936b726d6474f50283289e92ab5c7297081a54b9e70fce87603506dedd6734bab3c1567ee483cd4bcb0e669d9d97866ca274f178841dafc2acfdcd10cb0e2d07db244ff4b1d23afe253831f142083d912a7164a3425f82c95675298cf3c5eb3e096bbc95e44ecffafbb585738723c0adbe11f16c311a6cddde630b9c304717ce5b09247d482f32709ea71ced16ba930a554f9949c1acbecf")
	expedctedMACSignature, _ := hex.DecodeString("8e6e5ef63a4e8d6aa2cfb1c5fe1831498862f69d7de32af4f9895180e4b494e6")

	encryptedSig, macSig := ake.generateEncryptedSignature()
	assertDeepEquals(t, encryptedSig, expectedEncryptedSignature)
	assertDeepEquals(t, macSig, expedctedMACSignature)
}
