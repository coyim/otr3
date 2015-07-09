package otr3

import (
	"encoding/hex"
	"math/big"
	"testing"
)

var (
	r                        []byte
	x, y, gx, gy             *big.Int
	expectedEncryptedGxValue []byte
	expectedHashedGxValue    []byte
	expectedSharedSecret     *big.Int
)

func init() {
	x, _ = new(big.Int).SetString("bbcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd", 16)
	y, _ = new(big.Int).SetString("abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd", 16)
	r, _ = hex.DecodeString("abcdabcdabcdabcdabcdabcdabcdabcd")
	gx, _ = new(big.Int).SetString("75dfab5a1eab059052d0ad881c4938d52669630d61833a367155d67d03a457f619683d0fa829781e974fd24f6865e8128a9312a167b77326a87dea032fc31784d05b18b9cbafebe162ae9b5369f8b0c5911cf1be757f45f2a674be5126a714a6366c28086b3c7088911dcc4e5fb1481ad70a5237b8e4a6aff4954c2ca6df338b9f08691e4c0defe12689b37d4df30ddef2687f789fcf623c5d0cf6f09b7e5e69f481d5fd1b24a77636fb676e6d733d129eb93e81189340233044766a36eb07d", 16)
	gy, _ = new(big.Int).SetString("2cdacabb00e63d8949aa85f7e6a095b1ee81a60779e58f8938ff1a7ed1e651d954bd739162e699cc73b820728af53aae60a46d529620792ddf839c5d03d2d4e92137a535b27500e3b3d34d59d0cd460d1f386b5eb46a7404b15c1ef84840697d2d3d2405dcdda351014d24a8717f7b9c51f6c84de365fea634737ae18ba22253a8e15249d9beb2dded640c6c0d74e4f7e19161cf828ce3ffa9d425fb68c0fddcaa7cbe81a7a5c2c595cce69a255059d9e5c04b49fb15901c087e225da850ff27", 16)

	expectedEncryptedGxValue, _ = hex.DecodeString("5dd6a5999be73a99b80bdb78194a125f3067bd79e69c648b76a068117a8c4d0f36f275305423a933541937145d85ab4618094cbafbe4db0c0081614c1ff0f516c3dc4f352e9c92f88e4883166f12324d82240a8f32874c3d6bc35acedb8d501aa0111937a4859f33aa9b43ec342d78c3a45a5939c1e58e6b4f02725c1922f3df8754d1e1ab7648f558e9043ad118e63603b3ba2d8cbfea99a481835e42e73e6cd6019840f4470b606e168b1cd4a1f401c3dc52525d79fa6b959a80d4e11f1ec3a7984cf9")
	expectedHashedGxValue, _ = hex.DecodeString("5265b02c1f43d43335e88ddcaf9f1e08e41011fc49e58f68f8d977f9d2a9cc52")

	expectedSharedSecret, _ = new(big.Int).SetString("b15e9eb80f16f4beabcf7ac44c06f0b69b9f890a86a11b6cc2fd29e0f7cd15d9af7c052c4c55dfce929783e339ef094eedcfcaeb9edf896b7e201d46f16ba42dbec0a9738daa37c47a598849735b8b9ac8c98578431f8c7a6a54944ec6d830cb0ffcdf31d39cb8414bd3ddae0c483daf4e80a5990f7618edf648e68935126639d1752f49b2b8a83b170f39dd7d2a2c4ab99cb28684df2c6ee1feff9d171c25059eb6920bdf4cdab2fc0aed4aafeb66a51e938db8ca80881ad219413ecf7e0257", 16)
}

func TestDHCommitMessage(t *testing.T) {
	var ake AKE
	ake.protocolVersion = 0x0003
	ake.senderInstanceTag = 0x00000001
	ake.receiverInstanceTag = 0x00000001
	ake.Rand = fixedRand([]string{hex.EncodeToString(x.Bytes()), hex.EncodeToString(r[:])})

	var out []byte
	out = appendShort(out, ake.protocolVersion)
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
	ake.protocolVersion = 0x0003
	ake.senderInstanceTag = 0x00000001
	ake.receiverInstanceTag = 0x00000001
	ake.Rand = fixedRand([]string{hex.EncodeToString(x.Bytes()), hex.EncodeToString(r[:])})
	expectedGyValue, _ := new(big.Int).SetString("075dfab5a1eab059052d0ad881c4938d52669630d61833a367155d67d03a457f619683d0fa829781e974fd24f6865e8128a9312a167b77326a87dea032fc31784d05b18b9cbafebe162ae9b5369f8b0c5911cf1be757f45f2a674be5126a714a6366c28086b3c7088911dcc4e5fb1481ad70a5237b8e4a6aff4954c2ca6df338b9f08691e4c0defe12689b37d4df30ddef2687f789fcf623c5d0cf6f09b7e5e69f481d5fd1b24a77636fb676e6d733d129eb93e81189340233044766a36eb07d", 16)

	var out []byte
	out = appendShort(out, ake.protocolVersion)
	out = append(out, msgTypeDHKey)
	out = appendWord(out, ake.senderInstanceTag)
	out = appendWord(out, ake.receiverInstanceTag)
	out = appendMPI(out, expectedGyValue)

	result, err := ake.DHKeyMessage()
	assertEquals(t, err, nil)
	assertDeepEquals(t, result, out)
}

func TestRevealSigMessage(t *testing.T) {
	var ake AKE
	ake.protocolVersion = 0x0003
	ake.senderInstanceTag = 0x000000010
	ake.receiverInstanceTag = 0x00000001
	copy(ake.r[:], r)
	ake.x = x
	ake.gx = gx
	ake.gy = gy
	ake.myKeyId = 1

	expectedEncryptedSignature, _ := hex.DecodeString("000001d2dda2d4ef365711c172dad92804b201fcd2fdd6444568ebf0844019fb65ca4f5f57031936f9a339e08bfd4410905ab86c5d6f73e6c94de6a207f373beff3f7676faee7b1d3be21e630fe42e95db9d4ac559252bff530481301b590e2163b99bde8aa1b07448bf7252588e317b0ba2fc52f85a72a921ba757785b949e5e682341d98800aa180aa0bd01f51180d48260e4358ffae72a97f652f02eb6ae3bc6a25a317d0ca5ed0164a992240baac8e043f848332d22c10a46d12c745dc7b1b0ee37fd14614d4b69d500b8ce562040e3a4bfdd1074e2312d3e3e4c68bd15d70166855d8141f695b21c98c6055a5edb9a233925cf492218342450b806e58b3a821e5d1d2b9c6b9cbcba263908d7190a3428ace92572c064a328f86fa5b8ad2a9c76d5b9dcaeae5327f545b973795f7c655248141c2f82db0a2045e95c1936b726d6474f50283289e92ab5c7297081a54b9e70fce87603506dedd6734bab3c1567ee483cd4bcb0e669d9d97866ca274f178841dafc2acfdcd10cb0e2d07db244ff4b1d23afe253831f142083d912a7164a3425f82c95675298cf3c5eb3e096bbc95e44ecffafbb585738723c0adbe11f16c311a6cddde630b9c304717ce5b09247d482f32709ea71ced16ba930a554f9949c1acbecf")
	expedctedMACSignature, _ := hex.DecodeString("8e6e5ef63a4e8d6aa2cfb1c5fe1831498862f69d7de32af4f9895180e4b494e6")

	var out []byte
	out = appendShort(out, ake.protocolVersion)
	out = append(out, msgTypeRevealSig)
	out = appendWord(out, ake.senderInstanceTag)
	out = appendWord(out, ake.receiverInstanceTag)
	out = appendData(out, ake.r[:])
	out = append(out, expectedEncryptedSignature...)
	out = append(out, expedctedMACSignature[:20]...)

	result := ake.RevealSigMessage()
	assertDeepEquals(t, result, out)
}

func TestSigMessage(t *testing.T) {
	var ake AKE
	ake.protocolVersion = 0x0003
	ake.senderInstanceTag = 0x000000010
	ake.receiverInstanceTag = 0x00000001
	ake.y = y
	ake.gx = gx
	ake.gy = gy
	ake.myKeyId = 1

	expectedEncryptedSignature, _ := hex.DecodeString("000001d2b4f6ac650cc1d28f61a3b9bdf3cd60e2d1ea55d4c56e9f954eb22e10764861fb40d69917f5c4249fa701f3c04fae9449cd13a5054861f95fbc5775fc3cfd931cf5cc1a89eac82e7209b607c4fbf18df945e23bd0e91365fcc6c5dac072703dd8e2287372107f6a2cbb9139f5e82108d4cbcc1c6cdfcc772014136e756338745e2210d42c6e3ec4e9cf87fa8ebd8190e00f3a54bec86ee06cb7664059bb0fa79529e9d2e563ffecc5561477b3ba6bbf4ac679624b6da69a85822ed5c6ceb56a98740b1002026c503c39badab13b5d5ec948bbb961f0c90e68894a1fb70645a8e21ffe6b78e2e4ee62a62c48bd54e3d27c1166d098791518b53a10c409b5e55d16555b721a7750b7084e8972540bf0f1d76602e9b5fd58f94ed2dbf69fafccef84fdca2f9d800346b2358a200db060d8cf1b984a5213d02f7c27e452ad1cd893b0a668aaf6733809c31a392fc6cfc754691aca9a51582b636b92ea10abd661dd88bfd4c5f19b3ce265951728637b23fff7f7c0638721b6a01b3f1c3e923c10ea37d4e240fd973647d34dde6991cc3a04ce459c23e3ee2a858912ff78f405bbd9951935a120017904537db50f6e9e29338938f2b45ed323fc508d02fd0a0703e53ffc1889bccdec87e7c3d87e442fe29a7654d1")
	expedctedMACSignature, _ := hex.DecodeString("66b47e29be91a7cf4803d731921482fd514b4a53a9dd1639b17705c90185f91d")

	var out []byte
	out = appendShort(out, ake.protocolVersion)
	out = append(out, msgTypeSig)
	out = appendWord(out, ake.senderInstanceTag)
	out = appendWord(out, ake.receiverInstanceTag)
	out = append(out, expectedEncryptedSignature...)
	out = append(out, expedctedMACSignature[:20]...)
	result := ake.SigMessage()
	assertDeepEquals(t, result, out)
}

func Test_encryptedGx(t *testing.T) {
	var ake AKE
	ake.gx = gx
	encryptGx, err := ake.encryptedGx()
	assertEquals(t, err, nil)
	assertEquals(t, len(encryptGx), len(appendMPI([]byte{}, ake.gx)))
}

func Test_hashedGx(t *testing.T) {
	var ake AKE
	ake.gx = gx
	hashedGx := ake.hashedGx()
	assertDeepEquals(t, hashedGx, expectedHashedGxValue)
}

func Test_calcDHSharedSecret(t *testing.T) {
	var bob AKE
	bob.x = x
	bob.gy = gy

	sharedSecretB := bob.calcDHSharedSecret(true)
	assertDeepEquals(t, sharedSecretB, expectedSharedSecret)

	var alice AKE
	alice.y = y
	alice.gx = gx

	sharedSecretA := alice.calcDHSharedSecret(false)
	assertDeepEquals(t, sharedSecretA, expectedSharedSecret)
}

func Test_calcAKEKeys(t *testing.T) {
	var bob AKE
	bob.x = x
	bob.gy = gy

	bob.calcAKEKeys(bob.calcDHSharedSecret(true))
	assertEquals(t, hex.EncodeToString(bob.ssid[:]), "9cee5d2c7edbc86d")
	assertEquals(t, hex.EncodeToString(bob.revealKey.c[:]), "5745340b350364a02a0ac1467a318dcc")
	assertEquals(t, hex.EncodeToString(bob.sigKey.c[:]), "d942cc80b66503414c05e3752d9ba5c4")
	assertEquals(t, hex.EncodeToString(bob.revealKey.m1[:]), "d3251498fb9d977d07392a96eafb8c048d6bc67064bd7da72aa38f20f87a2e3d")
	assertEquals(t, hex.EncodeToString(bob.revealKey.m2[:]), "79c101a78a6c5819547a36b4813c84a8ac553d27a5d4b58be45dd0f3a67d3ca6")
	assertEquals(t, hex.EncodeToString(bob.sigKey.m1[:]), "b6254b8eab0ad98152949454d23c8c9b08e4e9cf423b27edc09b1975a76eb59c")
	assertEquals(t, hex.EncodeToString(bob.sigKey.m2[:]), "954be27015eeb0455250144d906e83e7d329c49581aea634c4189a3c981184f5")

	var alice AKE
	alice.y = y
	alice.gx = gx

	alice.calcAKEKeys(alice.calcDHSharedSecret(false))
	assertEquals(t, hex.EncodeToString(alice.ssid[:]), "9cee5d2c7edbc86d")
	assertEquals(t, hex.EncodeToString(alice.revealKey.c[:]), "5745340b350364a02a0ac1467a318dcc")
	assertEquals(t, hex.EncodeToString(alice.sigKey.c[:]), "d942cc80b66503414c05e3752d9ba5c4")
	assertEquals(t, hex.EncodeToString(alice.revealKey.m1[:]), "d3251498fb9d977d07392a96eafb8c048d6bc67064bd7da72aa38f20f87a2e3d")
	assertEquals(t, hex.EncodeToString(alice.revealKey.m2[:]), "79c101a78a6c5819547a36b4813c84a8ac553d27a5d4b58be45dd0f3a67d3ca6")
	assertEquals(t, hex.EncodeToString(alice.sigKey.m1[:]), "b6254b8eab0ad98152949454d23c8c9b08e4e9cf423b27edc09b1975a76eb59c")
	assertEquals(t, hex.EncodeToString(alice.sigKey.m2[:]), "954be27015eeb0455250144d906e83e7d329c49581aea634c4189a3c981184f5")
}

func Test_generateRevealKeyEncryptedSignature(t *testing.T) {
	var ake AKE
	ake.x = x
	ake.gx = gx
	ake.gy = gy
	ake.myKeyId = 1

	ake.calcAKEKeys(ake.calcDHSharedSecret(true))
	expectedEncryptedSignature, _ := hex.DecodeString("000001d2dda2d4ef365711c172dad92804b201fcd2fdd6444568ebf0844019fb65ca4f5f57031936f9a339e08bfd4410905ab86c5d6f73e6c94de6a207f373beff3f7676faee7b1d3be21e630fe42e95db9d4ac559252bff530481301b590e2163b99bde8aa1b07448bf7252588e317b0ba2fc52f85a72a921ba757785b949e5e682341d98800aa180aa0bd01f51180d48260e4358ffae72a97f652f02eb6ae3bc6a25a317d0ca5ed0164a992240baac8e043f848332d22c10a46d12c745dc7b1b0ee37fd14614d4b69d500b8ce562040e3a4bfdd1074e2312d3e3e4c68bd15d70166855d8141f695b21c98c6055a5edb9a233925cf492218342450b806e58b3a821e5d1d2b9c6b9cbcba263908d7190a3428ace92572c064a328f86fa5b8ad2a9c76d5b9dcaeae5327f545b973795f7c655248141c2f82db0a2045e95c1936b726d6474f50283289e92ab5c7297081a54b9e70fce87603506dedd6734bab3c1567ee483cd4bcb0e669d9d97866ca274f178841dafc2acfdcd10cb0e2d07db244ff4b1d23afe253831f142083d912a7164a3425f82c95675298cf3c5eb3e096bbc95e44ecffafbb585738723c0adbe11f16c311a6cddde630b9c304717ce5b09247d482f32709ea71ced16ba930a554f9949c1acbecf")
	expedctedMACSignature, _ := hex.DecodeString("8e6e5ef63a4e8d6aa2cfb1c5fe1831498862f69d7de32af4f9895180e4b494e6")

	encryptedSig, macSig := ake.generateEncryptedSignature(&ake.revealKey, true)
	assertDeepEquals(t, encryptedSig, expectedEncryptedSignature)
	assertDeepEquals(t, macSig, expedctedMACSignature)
}

func Test_generateSigKeyEncryptedSignature(t *testing.T) {
	var ake AKE
	ake.y = y
	ake.gx = gx
	ake.gy = gy
	ake.myKeyId = 1

	ake.calcAKEKeys(ake.calcDHSharedSecret(false))
	expectedEncryptedSignature, _ := hex.DecodeString("000001d2b4f6ac650cc1d28f61a3b9bdf3cd60e2d1ea55d4c56e9f954eb22e10764861fb40d69917f5c4249fa701f3c04fae9449cd13a5054861f95fbc5775fc3cfd931cf5cc1a89eac82e7209b607c4fbf18df945e23bd0e91365fcc6c5dac072703dd8e2287372107f6a2cbb9139f5e82108d4cbcc1c6cdfcc772014136e756338745e2210d42c6e3ec4e9cf87fa8ebd8190e00f3a54bec86ee06cb7664059bb0fa79529e9d2e563ffecc5561477b3ba6bbf4ac679624b6da69a85822ed5c6ceb56a98740b1002026c503c39badab13b5d5ec948bbb961f0c90e68894a1fb70645a8e21ffe6b78e2e4ee62a62c48bd54e3d27c1166d098791518b53a10c409b5e55d16555b721a7750b7084e8972540bf0f1d76602e9b5fd58f94ed2dbf69fafccef84fdca2f9d800346b2358a200db060d8cf1b984a5213d02f7c27e452ad1cd893b0a668aaf6733809c31a392fc6cfc754691aca9a51582b636b92ea10abd661dd88bfd4c5f19b3ce265951728637b23fff7f7c0638721b6a01b3f1c3e923c10ea37d4e240fd973647d34dde6991cc3a04ce459c23e3ee2a858912ff78f405bbd9951935a120017904537db50f6e9e29338938f2b45ed323fc508d02fd0a0703e53ffc1889bccdec87e7c3d87e442fe29a7654d1")
	expedctedMACSignature, _ := hex.DecodeString("66b47e29be91a7cf4803d731921482fd514b4a53a9dd1639b17705c90185f91d")

	encryptedSig, macSig := ake.generateEncryptedSignature(&ake.sigKey, false)
	assertDeepEquals(t, encryptedSig, expectedEncryptedSignature)
	assertDeepEquals(t, macSig, expedctedMACSignature)
}
