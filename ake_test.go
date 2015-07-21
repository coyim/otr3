package otr3

import (
	"encoding/hex"
	"errors"
	"io"
	"math/big"
	"testing"
)

func bytesFromHex(s string) []byte {
	val, _ := hex.DecodeString(s)
	return val
}

var (
	fixedr                   = bytesFromHex("abcdabcdabcdabcdabcdabcdabcdabcd")
	fixedx                   = bnFromHex("bbcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd")
	fixedy                   = bnFromHex("abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd")
	fixedgx                  = bnFromHex("75dfab5a1eab059052d0ad881c4938d52669630d61833a367155d67d03a457f619683d0fa829781e974fd24f6865e8128a9312a167b77326a87dea032fc31784d05b18b9cbafebe162ae9b5369f8b0c5911cf1be757f45f2a674be5126a714a6366c28086b3c7088911dcc4e5fb1481ad70a5237b8e4a6aff4954c2ca6df338b9f08691e4c0defe12689b37d4df30ddef2687f789fcf623c5d0cf6f09b7e5e69f481d5fd1b24a77636fb676e6d733d129eb93e81189340233044766a36eb07d")
	fixedgy                  = bnFromHex("2cdacabb00e63d8949aa85f7e6a095b1ee81a60779e58f8938ff1a7ed1e651d954bd739162e699cc73b820728af53aae60a46d529620792ddf839c5d03d2d4e92137a535b27500e3b3d34d59d0cd460d1f386b5eb46a7404b15c1ef84840697d2d3d2405dcdda351014d24a8717f7b9c51f6c84de365fea634737ae18ba22253a8e15249d9beb2dded640c6c0d74e4f7e19161cf828ce3ffa9d425fb68c0fddcaa7cbe81a7a5c2c595cce69a255059d9e5c04b49fb15901c087e225da850ff27")
	expectedEncryptedGxValue = bytesFromHex("5dd6a5999be73a99b80bdb78194a125f3067bd79e69c648b76a068117a8c4d0f36f275305423a933541937145d85ab4618094cbafbe4db0c0081614c1ff0f516c3dc4f352e9c92f88e4883166f12324d82240a8f32874c3d6bc35acedb8d501aa0111937a4859f33aa9b43ec342d78c3a45a5939c1e58e6b4f02725c1922f3df8754d1e1ab7648f558e9043ad118e63603b3ba2d8cbfea99a481835e42e73e6cd6019840f4470b606e168b1cd4a1f401c3dc52525d79fa6b959a80d4e11f1ec3a7984cf9")
	expectedHashedGxValue    = bytesFromHex("a3f2c4b9e3a7d1f565157ae7b0e71c721d59d3c79d39e5e4e8d08cb8464ff857")
	expectedSharedSecret     = bnFromHex("b15e9eb80f16f4beabcf7ac44c06f0b69b9f890a86a11b6cc2fd29e0f7cd15d9af7c052c4c55dfce929783e339ef094eedcfcaeb9edf896b7e201d46f16ba42dbec0a9738daa37c47a598849735b8b9ac8c98578431f8c7a6a54944ec6d830cb0ffcdf31d39cb8414bd3ddae0c483daf4e80a5990f7618edf648e68935126639d1752f49b2b8a83b170f39dd7d2a2c4ab99cb28684df2c6ee1feff9d171c25059eb6920bdf4cdab2fc0aed4aafeb66a51e938db8ca80881ad219413ecf7e0257")
	expectedC                = bytesFromHex("d942cc80b66503414c05e3752d9ba5c4")
	expectedM1               = bytesFromHex("b6254b8eab0ad98152949454d23c8c9b08e4e9cf423b27edc09b1975a76eb59c")
	expectedM2               = bytesFromHex("954be27015eeb0455250144d906e83e7d329c49581aea634c4189a3c981184f5")
	alicePrivateKey          = parseIntoPrivateKey("000000000080c81c2cb2eb729b7e6fd48e975a932c638b3a9055478583afa46755683e30102447f6da2d8bec9f386bbb5da6403b0040fee8650b6ab2d7f32c55ab017ae9b6aec8c324ab5844784e9a80e194830d548fb7f09a0410df2c4d5c8bc2b3e9ad484e65412be689cf0834694e0839fb2954021521ffdffb8f5c32c14dbf2020b3ce7500000014da4591d58def96de61aea7b04a8405fe1609308d000000808ddd5cb0b9d66956e3dea5a915d9aba9d8a6e7053b74dadb2fc52f9fe4e5bcc487d2305485ed95fed026ad93f06ebb8c9e8baf693b7887132c7ffdd3b0f72f4002ff4ed56583ca7c54458f8c068ca3e8a4dfa309d1dd5d34e2a4b68e6f4338835e5e0fb4317c9e4c7e4806dafda3ef459cd563775a586dd91b1319f72621bf3f00000080b8147e74d8c45e6318c37731b8b33b984a795b3653c2cd1d65cc99efe097cb7eb2fa49569bab5aab6e8a1c261a27d0f7840a5e80b317e6683042b59b6dceca2879c6ffc877a465be690c15e4a42f9a7588e79b10faac11b1ce3741fcef7aba8ce05327a2c16d279ee1b3d77eb783fb10e3356caa25635331e26dd42b8396c4d00000001420bec691fea37ecea58a5c717142f0b804452f57")
	bobPrivateKey            = parseIntoPrivateKey("000000000080a5138eb3d3eb9c1d85716faecadb718f87d31aaed1157671d7fee7e488f95e8e0ba60ad449ec732710a7dec5190f7182af2e2f98312d98497221dff160fd68033dd4f3a33b7c078d0d9f66e26847e76ca7447d4bab35486045090572863d9e4454777f24d6706f63e02548dfec2d0a620af37bbc1d24f884708a212c343b480d00000014e9c58f0ea21a5e4dfd9f44b6a9f7f6a9961a8fa9000000803c4d111aebd62d3c50c2889d420a32cdf1e98b70affcc1fcf44d59cca2eb019f6b774ef88153fb9b9615441a5fe25ea2d11b74ce922ca0232bd81b3c0fcac2a95b20cb6e6c0c5c1ace2e26f65dc43c751af0edbb10d669890e8ab6beea91410b8b2187af1a8347627a06ecea7e0f772c28aae9461301e83884860c9b656c722f0000008065af8625a555ea0e008cd04743671a3cda21162e83af045725db2eb2bb52712708dc0cc1a84c08b3649b88a966974bde27d8612c2861792ec9f08786a246fcadd6d8d3a81a32287745f309238f47618c2bd7612cb8b02d940571e0f30b96420bcd462ff542901b46109b1e5ad6423744448d20a57818a8cbb1647d0fea3b664e0000001440f9f2eb554cb00d45a5826b54bfa419b6980e48")
)

func Test_dhCommitMessage(t *testing.T) {
	rnd := fixedRand([]string{hex.EncodeToString(fixedx.Bytes()), hex.EncodeToString(fixedr[:])})
	ake := AKE{
		akeContext: newAkeContext(otrV3{}, rnd),
	}

	ake.ourKey = bobPrivateKey
	ake.senderInstanceTag = 0x00000001
	ake.receiverInstanceTag = 0x00000001

	var out []byte
	out = appendShort(out, ake.protocolVersion())
	out = append(out, msgTypeDHCommit)
	out = appendWord(out, ake.senderInstanceTag)
	out = appendWord(out, ake.receiverInstanceTag)
	out = appendData(out, expectedEncryptedGxValue)
	out = appendData(out, expectedHashedGxValue)

	result, err := ake.dhCommitMessage()
	assertEquals(t, err, nil)
	assertDeepEquals(t, result, out)
}

func Test_dhKeyMessage(t *testing.T) {
	rnd := fixedRand([]string{hex.EncodeToString(fixedx.Bytes()), hex.EncodeToString(fixedr[:])})
	ake := AKE{
		akeContext: newAkeContext(otrV3{}, rnd),
	}

	ake.ourKey = alicePrivateKey
	ake.senderInstanceTag = 0x00000001
	ake.receiverInstanceTag = 0x00000001
	expectedGyValue := bnFromHex("075dfab5a1eab059052d0ad881c4938d52669630d61833a367155d67d03a457f619683d0fa829781e974fd24f6865e8128a9312a167b77326a87dea032fc31784d05b18b9cbafebe162ae9b5369f8b0c5911cf1be757f45f2a674be5126a714a6366c28086b3c7088911dcc4e5fb1481ad70a5237b8e4a6aff4954c2ca6df338b9f08691e4c0defe12689b37d4df30ddef2687f789fcf623c5d0cf6f09b7e5e69f481d5fd1b24a77636fb676e6d733d129eb93e81189340233044766a36eb07d")

	var out []byte
	out = appendShort(out, ake.protocolVersion())
	out = append(out, msgTypeDHKey)
	out = appendWord(out, ake.senderInstanceTag)
	out = appendWord(out, ake.receiverInstanceTag)
	out = appendMPI(out, expectedGyValue)

	result, err := ake.dhKeyMessage()
	assertEquals(t, err, nil)
	assertDeepEquals(t, result, out)
}

func Test_dhKeyMessage_returnsAnErrorIfTheresNotEnoughRandomnessForAnMPI(t *testing.T) {
	rnd := fixedRand([]string{"0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A"})
	ake := AKE{akeContext: newAkeContext(otrV3{}, rnd)}
	_, err := ake.dhKeyMessage()
	assertDeepEquals(t, err, errors.New("otr: short read from random source"))
}

func Test_revealSigMessage(t *testing.T) {
	rnd := fixedRand([]string{"cbcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd"})
	ake := AKE{
		akeContext: newAkeContext(otrV3{}, rnd),
	}

	ake.senderInstanceTag = 0x000000010
	ake.receiverInstanceTag = 0x00000001
	ake.ourKey = bobPrivateKey
	copy(ake.r[:], fixedr)
	ake.x = fixedx
	ake.gx = fixedgx
	ake.gy = fixedgy
	ake.ourKeyID = 1
	expectedEncryptedSignature := bytesFromHex("000001d2dda2d4ef365711c172dad92804b201fcd2fdd6444568ebf0844019fb65ca4f5f57031936f9a339e08bfd4410905ab86c5d6f73e6c94de6a207f373beff3f7676faee7b1d3be21e630fe42e95db9d4ac559252bff530481301b590e2163b99bde8aa1b07448bf7252588e317b0ba2fc52f85a72a921ba757785b949e5e682341d98800aa180aa0bd01f51180d48260e4358ffae72a97f652f02eb6ae3bc6a25a317d0ca5ed0164a992240baac8e043f848332d22c10a46d12c745dc7b1b0ee37fd14614d4b69d500b8ce562040e3a4bfdd1074e2312d3e3e4c68bd15d70166855d8141f695b21c98c6055a5edb9a233925cf492218342450b806e58b3a821e5d1d2b9c6b9cbcba263908d7190a3428ace92572c064a328f86fa5b8ad2a9c76d5b9dcaeae5327f545b973795f7c655248141c2f82db0a2045e95c1936b726d6474f50283289e92ab5c7297081a54b9e70fce87603506dedd6734bab3c1567ee483cd4bcb0e669d9d97866ca274f178841dafc2acfdcd10cb0e2d07db244ff4b1d23afe253831f142083d912a7164a3425f82c95675298cf3c5eb3e096bbc95e44ecffafbb585738723c0adbe11f16c311a6cddde630b9c304717ce5b09247d482f32709ea71ced16ba930a554f9949c1acbecf")
	expedctedMACSignature := bytesFromHex("8e6e5ef63a4e8d6aa2cfb1c5fe1831498862f69d7de32af4f9895180e4b494e6")

	var out []byte
	out = appendShort(out, ake.protocolVersion())
	out = append(out, msgTypeRevealSig)
	out = appendWord(out, ake.senderInstanceTag)
	out = appendWord(out, ake.receiverInstanceTag)
	out = appendData(out, ake.r[:])
	out = append(out, expectedEncryptedSignature...)
	out = append(out, expedctedMACSignature[:20]...)

	result, err := ake.revealSigMessage()
	assertEquals(t, err, nil)
	assertDeepEquals(t, result, out)
}

func Test_processDHKey(t *testing.T) {
	ake := AKE{
		akeContext: newAkeContext(otrV2{}, fixtureRand()),
	}
	ake.gy = fixedgy

	msg := appendShort([]byte{}, ake.protocolVersion())
	msg = append(msg, msgTypeDHKey)
	msg = appendMPI(msg, ake.gy)

	isSame, err := ake.processDHKey(msg)
	assertEquals(t, err, nil)
	assertDeepEquals(t, isSame, true)
}

func Test_processDHKeyNotSame(t *testing.T) {
	ake := AKE{
		akeContext: newAkeContext(otrV2{}, fixtureRand()),
	}
	ake.gy = fixedgy

	msg := appendShort([]byte{}, ake.protocolVersion())
	msg = append(msg, msgTypeDHKey)
	msg = appendMPI(msg, fixedgx)

	isSame, err := ake.processDHKey(msg)
	assertEquals(t, err, nil)
	assertDeepEquals(t, isSame, false)
}

func Test_processDHKeyHavingError(t *testing.T) {
	invalidGy := bnFromHex("751234566dfab5a1eab059052d0ad881c4938d52669630d61833a367155d67d03a457f619683d0fa829781e974fd24f6865e8128a9312a167b77326a87dea032fc31784d05b18b9cbafebe162ae9b5369f8b0c5911cf1be757f45f2a674be5126a714a6366c28086b3c7088911dcc4e5fb1481ad70a5237b8e4a6aff4954c2ca6df338b9f08691e4c0defe12689b37d4df30ddef2687f789fcf623c5d0cf6f09b7e5e69f481d5fd1b24a77636fb676e6d733d129eb93e81189340233044766a36eb07d")

	ake := AKE{
		akeContext: newAkeContext(otrV2{}, fixtureRand()),
	}
	ake.gy = fixedgy

	msg := appendShort([]byte{}, ake.protocolVersion())
	msg = append(msg, msgTypeDHKey)
	msg = appendMPI(msg, invalidGy)

	isSame, err := ake.processDHKey(msg)
	assertEquals(t, err.Error(), "otr: DH value out of range")
	assertDeepEquals(t, isSame, false)
}

func Test_processEncryptedSig(t *testing.T) {
	rnd := fixedRand([]string{})
	ake := AKE{
		akeContext: newAkeContext(otrV3{}, rnd),
	}
	ake.x = fixedx
	ake.gx = fixedgx
	ake.gy = fixedgy
	ake.ourKeyID = 1
	s := ake.calcDHSharedSecret(true)
	ake.calcAKEKeys(s)

	_, encryptedSig, _ := extractData(bytesFromHex("000001d2dda2d4ef365711c172dad92804b201fcd2fdd6444568ebf0844019fb65ca4f5f57031936f9a339e08bfd4410905ab86c5d6f73e6c94de6a207f373beff3f7676faee7b1d3be21e630fe42e95db9d4ac559252bff530481301b590e2163b99bde8aa1b07448bf7252588e317b0ba2fc52f85a72a921ba757785b949e5e682341d98800aa180aa0bd01f51180d48260e4358ffae72a97f652f02eb6ae3bc6a25a317d0ca5ed0164a992240baac8e043f848332d22c10a46d12c745dc7b1b0ee37fd14614d4b69d500b8ce562040e3a4bfdd1074e2312d3e3e4c68bd15d70166855d8141f695b21c98c6055a5edb9a233925cf492218342450b806e58b3a821e5d1d2b9c6b9cbcba263908d7190a3428ace92572c064a328f86fa5b8ad2a9c76d5b9dcaeae5327f545b973795f7c655248141c2f82db0a2045e95c1936b726d6474f50283289e92ab5c7297081a54b9e70fce87603506dedd6734bab3c1567ee483cd4bcb0e669d9d97866ca274f178841dafc2acfdcd10cb0e2d07db244ff4b1d23afe253831f142083d912a7164a3425f82c95675298cf3c5eb3e096bbc95e44ecffafbb585738723c0adbe11f16c311a6cddde630b9c304717ce5b09247d482f32709ea71ced16ba930a554f9949c1acbecf"))
	macSignature := bytesFromHex("8e6e5ef63a4e8d6aa2cfb1c5fe1831498862f69d7de32af4f9895180e4b494e6")
	err := ake.processEncryptedSig(encryptedSig, macSignature[:20], &ake.revealKey, true)
	assertEquals(t, err, nil)
	assertEquals(t, ake.theirKeyID, uint32(1))
}

func Test_processEncryptedSigWithBadSignatureMACError(t *testing.T) {
	ake := AKE{}

	_, encryptedSig, _ := extractData(bytesFromHex("000001b2dda2d4ef365711c172dad92804b201fcd2fdd6444568ebf0844019fb65ca4f5f57031936f9a339e08bfd4410905ab86c5d6f73e6c94de6a207f373beff3f7676faee7b1d3be21e630fe42e95db9d4ac559252bff530481301b590e2163b99bde8aa1b07448bf7252588e317b0ba2fc52f85a72a921ba757785b949e5e682341d98800aa180aa0bd01f51180d48260e4358ffae72a97f652f02eb6ae3bc6a25a317d0ca5ed0164a992240baac8e043f848332d22c10a46d12c745dc7b1b0ee37fd14614d4b69d500b8ce562040e3a4bfdd1074e2312d3e3e4c68bd15d70166855d8141f695b21c98c6055a5edb9a233925cf492218342450b806e58b3a821e5d1d2b9c6b9cbcba263908d7190a3428ace92572c064a328f86fa5b8ad2a9c76d5b9dcaeae5327f545b973795f7c655248141c2f82db0a2045e95c1936b726d6474f50283289e92ab5c7297081a54b9e70fce87603506dedd6734bab3c1567ee483cd4bcb0e669d9d97866ca274f178841dafc2acfdcd10cb0e2d07db244ff4b1d23afe253831f142083d912a7164a3425f82c95675298cf3c5eb3e096bbc95e44ecffafbb585738723c0adbe11f16c311a6cddde630b9c304717ce5b09247d482f32709ea71ced16ba930a554f9949c1acbecf"))
	macSignature := bytesFromHex("8e6e5ef63a4e8d6aa2cfb1c5fe1831498862f69d7de32af4f9895180e4b494e6")
	err := ake.processEncryptedSig(encryptedSig, macSignature[:20], &ake.revealKey, true)
	assertEquals(t, err.Error(), "bad signature MAC in encrypted signature")
	assertEquals(t, ake.theirKeyID, uint32(0))
}

func Test_processEncryptedSigWithBadSignatureError(t *testing.T) {
	rnd := fixedRand([]string{})
	ake := AKE{
		akeContext: newAkeContext(otrV3{}, rnd),
	}
	ake.ourKey = bobPrivateKey
	ake.theirKey = &bobPrivateKey.PublicKey
	ake.x = fixedx
	ake.gx = fixedgx
	ake.gy = fixedgy
	ake.ourKeyID = 1
	s := ake.calcDHSharedSecret(true)
	ake.calcAKEKeys(s)

	_, encryptedSig, _ := extractData(bytesFromHex("000001d2dda2d4ef365711c172dad92804b201fcd2fdd6444568ebf0844019fb65ca4f5f57031936f9a339e08bfd4410905ab86c5d6f73e6c94de6a207f373beff3f7676faee7b1d3be21e630fe42e95db9d4ac559252bff530481301b590e2163b99bde8aa1b07448bf7252588e317b0ba2fc52f85a72a921ba757785b949e5e682341d98800aa180aa0bd01f51180d48260e4358ffae72a97f652f02eb6ae3bc6a25a317d0ca5ed0164a992240baac8e043f848332d22c10a46d12c745dc7b1b0ee37fd14614d4b69d500b8ce562040e3a4bfdd1074e2312d3e3e4c68bd15d70166855d8141f695b21c98c6055a5edb9a233925cf492218342450b806e58b3a821e5d1d2b9c6b9cbcba263908d7190a3428ace92572c064a328f86fa5b8ad2a9c76d5b9dcaeae5327f545b973795f7c655248141c2f82db0a2045e95c1936b726d6474f50283289e92ab5c7297081a54b9e70fce87603506dedd6734bab3c1567ee483cd4bcb0e669d9d97866ca274f178841dafc2acfdcd10cb0e2d07db244ff4b1d23afe253831f142083d912a7164a3425f82c95675298cf3c5eb3e096bbc95e44ecffafbb585738723c0adbe11f16c311a6cddde630b9c304717ce5b09247d482f32709ea71ced16ba930a554f9949c1acbeca"))
	macSignature := bytesFromHex("741f14776485e6c593928fd859afe1ab4896f1e6")
	err := ake.processEncryptedSig(encryptedSig, macSignature[:20], &ake.revealKey, true)
	assertEquals(t, err.Error(), "bad signature in encrypted signature")
	assertEquals(t, ake.theirKeyID, uint32(0))
}

func Test_processRevealSig(t *testing.T) {
	rnd := fixedRand([]string{"cbcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd"})
	bob := AKE{
		akeContext: newAkeContext(otrV3{}, rnd),
	}
	alice := AKE{
		akeContext: newAkeContext(otrV3{}, rnd),
	}

	bob.ourKey = bobPrivateKey
	copy(bob.r[:], fixedr)
	bob.x = fixedx
	bob.gx = fixedgx
	bob.gy = fixedgy
	bob.ourKeyID = 1
	msg, err := bob.revealSigMessage()

	alice.y = fixedy
	alice.gy = fixedgy
	alice.encryptedGx = bytesFromHex("5dd6a5999be73a99b80bdb78194a125f3067bd79e69c648b76a068117a8c4d0f36f275305423a933541937145d85ab4618094cbafbe4db0c0081614c1ff0f516c3dc4f352e9c92f88e4883166f12324d82240a8f32874c3d6bc35acedb8d501aa0111937a4859f33aa9b43ec342d78c3a45a5939c1e58e6b4f02725c1922f3df8754d1e1ab7648f558e9043ad118e63603b3ba2d8cbfea99a481835e42e73e6cd6019840f4470b606e168b1cd4a1f401c3dc52525d79fa6b959a80d4e11f1ec3a7984cf9")
	copy(alice.hashedGx[:], bytesFromHex("a3f2c4b9e3a7d1f565157ae7b0e71c721d59d3c79d39e5e4e8d08cb8464ff857"))
	err = alice.processRevealSig(msg)

	assertEquals(t, err, nil)
	assertEquals(t, alice.theirKeyID, uint32(1))
}

func Test_processSig(t *testing.T) {
	rnd := fixedRand([]string{"cbcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd"})
	ake := AKE{
		akeContext: newAkeContext(otrV3{}, rnd),
	}

	ake.ourKey = bobPrivateKey
	ake.y = fixedy
	ake.gx = fixedgx
	ake.gy = fixedgy
	ake.ourKeyID = 1
	result, err := ake.sigMessage()

	err = ake.processSig(result)

	assertEquals(t, err, nil)
	assertEquals(t, ake.theirKeyID, uint32(1))
}

func Test_processSig_returnsErrorIfDataIsNotLongEnoughForHeader(t *testing.T) {
	ake := AKE{akeContext: newAkeContext(otrV2{}, fixtureRand())}
	err := ake.processSig([]byte{0x01, 0x00})
	assertDeepEquals(t, err, errors.New("otr: invalid OTR message"))
}

func Test_processSig_returnsErrorIfTheSignatureDataIsInvalid(t *testing.T) {
	ake := AKE{akeContext: newAkeContext(otrV2{}, fixtureRand())}
	err := ake.processSig([]byte{0x01, 0x00, 0x01, 0x01, 0x01, 0x00})
	assertDeepEquals(t, err, errors.New("otr: corrupt signature message"))
}

func Test_processRevealSig_returnsErrorIfDataIsNotLongEnoughForHeader(t *testing.T) {
	ake := AKE{akeContext: newAkeContext(otrV2{}, fixtureRand())}
	err := ake.processRevealSig([]byte{0x01, 0x00})
	assertDeepEquals(t, err, errors.New("otr: invalid OTR message"))
}

func Test_processRevealSig_returnsErrorIfTheRDataIsInvalid(t *testing.T) {
	ake := AKE{akeContext: newAkeContext(otrV2{}, fixtureRand())}
	err := ake.processRevealSig([]byte{0x01, 0x00, 0x01, 0x01, 0x01, 0x00})
	assertDeepEquals(t, err, errors.New("otr: corrupt reveal signature message"))
}

func Test_processRevealSig_returnsErrorIfTheSignatureDataIsInvalid(t *testing.T) {
	ake := AKE{akeContext: newAkeContext(otrV2{}, fixtureRand())}
	err := ake.processRevealSig([]byte{0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x01, 0x00, 0x00, 0x00, 0x02, 0x01})
	assertDeepEquals(t, err, errors.New("otr: corrupt reveal signature message"))
}

func Test_sigMessage(t *testing.T) {
	rnd := fixedRand([]string{"bbcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd"})
	ake := AKE{
		akeContext: newAkeContext(otrV3{}, rnd),
	}

	ake.ourKey = alicePrivateKey
	ake.senderInstanceTag = 0x000000010
	ake.receiverInstanceTag = 0x00000001
	ake.y = fixedy
	ake.gx = fixedgx
	ake.gy = fixedgy
	ake.ourKeyID = 1

	expectedEncryptedSignature, _ := hex.DecodeString("000001d2b4f6ac650cc1d28f61a3b9bdf3cd60e2d1ea55d4c56e9f954eb22e10764861fb40d69917f5c4249fa701f3c04fae9449cd13a5054861f95fbc5775fc3cfd931cf5cc1a89eac82e7209b607c4fbf18df945e23bd0e91365fcc6c5dac072703dd8e2287372107f6a2cbb9139f5e82108d4cbcc1c6cdfcc772014136e756338745e2210d42c6e3ec4e9cf87fa8ebd8190e00f3a54bec86ee06cb7664059bb0fa79529e9d2e563ffecc5561477b3ba6bbf4ac679624b6da69a85822ed5c6ceb56a98740b1002026c503c39badab13b5d5ec948bbb961f0c90e68894a1fb70645a8e21ffe6b78e2e4ee62a62c48bd54e3d27c1166d098791518b53a10c409b5e55d16555b721a7750b7084e8972540bf0f1d76602e9b5fd58f94ed2dbf69fafccef84fdca2f9d800346b2358a200db060d8cf1b984a5213d02f7c27e452ad1cd893b0a668aaf6733809c31a392fc6cfc754691aca9a51582b636b92ea10abd661dd88bfd4c5f19b3ce265951728637b23fff7f7c0638721b6a01b3f1c3e923c10ea37d4e240fd973647d34dde6991cc3a04ce459c23e3ee2a858912ff78f405bbd9951935a120017904537db50f6e9e29338938f2b45ed323fc508d02fd0a0703e53ffc1889bccdec87e7c3d87e442fe29a7654d1")
	expedctedMACSignature, _ := hex.DecodeString("66b47e29be91a7cf4803d731921482fd514b4a53a9dd1639b17705c90185f91d")

	var out []byte
	out = appendShort(out, ake.protocolVersion())
	out = append(out, msgTypeSig)
	out = appendWord(out, ake.senderInstanceTag)
	out = appendWord(out, ake.receiverInstanceTag)
	out = append(out, expectedEncryptedSignature...)
	out = append(out, expedctedMACSignature[:20]...)

	result, err := ake.sigMessage()
	assertEquals(t, err, nil)
	assertDeepEquals(t, result, out)
}

func Test_encrypt(t *testing.T) {
	rnd := fixedRand([]string{hex.EncodeToString(fixedx.Bytes())})
	ake := AKE{
		akeContext: newAkeContext(otrV3{}, rnd),
	}

	ake.gx = fixedgx
	io.ReadFull(ake.rand(), ake.r[:])

	encryptedGx, err := encrypt(ake.r[:], appendMPI(nil, ake.gx))
	assertEquals(t, err, nil)
	assertDeepEquals(t, len(encryptedGx), len(appendMPI([]byte{}, ake.gx)))
}

func Test_decrypt(t *testing.T) {
	rnd := fixedRand([]string{hex.EncodeToString(fixedx.Bytes())})
	ake := AKE{
		akeContext: newAkeContext(otrV3{}, rnd),
	}

	ake.gx = fixedgx
	io.ReadFull(ake.rand(), ake.r[:])

	encryptedGx, _ := encrypt(ake.r[:], appendMPI(nil, ake.gx))
	decryptedGx := encryptedGx
	err := decrypt(ake.r[:], decryptedGx, encryptedGx)

	assertEquals(t, err, nil)
	assertDeepEquals(t, decryptedGx, appendMPI([]byte{}, ake.gx))
}

func Test_sha256Sum(t *testing.T) {
	hashedGx := sha256Sum(appendMPI(nil, fixedgx))
	assertDeepEquals(t, hashedGx[:], expectedHashedGxValue)
}

func Test_checkDecryptedGxWithoutError(t *testing.T) {
	hashedGx := sha256Sum(appendMPI([]byte{}, fixedgx))
	err := checkDecryptedGx(appendMPI([]byte{}, fixedgx), hashedGx[:])
	assertDeepEquals(t, err, nil)
}

func Test_checkDecryptedGxWithError(t *testing.T) {
	hashedGx := sha256Sum(appendMPI([]byte{}, fixedgy))
	err := checkDecryptedGx(appendMPI([]byte{}, fixedgx), hashedGx[:])
	assertDeepEquals(t, err.Error(), "otr: bad commit MAC in reveal signature message")
}

func Test_extractGxWithoutError(t *testing.T) {
	gx, err := extractGx(appendMPI([]byte{}, fixedgx))
	assertDeepEquals(t, err, nil)
	assertDeepEquals(t, gx, fixedgx)
}

func Test_extractGxWithCorruptError(t *testing.T) {
	gx, err := extractGx(appendMPI(appendMPI([]byte{}, fixedgx), fixedy))
	assertDeepEquals(t, err.Error(), "otr: gx corrupt after decryption")
	assertDeepEquals(t, gx, fixedgx)
}

func Test_extractGx_returnsErrorWhenThereIsNotEnoughLengthForTheMPI(t *testing.T) {
	_, err := extractGx([]byte{0x00, 0x00, 0x00, 0x02, 0x01})
	assertDeepEquals(t, err, errors.New("otr: gx corrupt after decryption"))
}

func Test_extractGxWithRangeError(t *testing.T) {
	gx, err := extractGx(appendMPI([]byte{}, big.NewInt(1)))
	assertDeepEquals(t, gx, big.NewInt(1))
	assertDeepEquals(t, err.Error(), "otr: DH value out of range")
}

func Test_calcDHSharedSecret(t *testing.T) {
	var bob AKE
	bob.x = fixedx
	bob.gy = fixedgy

	sharedSecretB := bob.calcDHSharedSecret(true)
	assertDeepEquals(t, sharedSecretB, expectedSharedSecret)

	var alice AKE
	alice.y = fixedy
	alice.gx = fixedgx

	sharedSecretA := alice.calcDHSharedSecret(false)

	assertDeepEquals(t, sharedSecretA, expectedSharedSecret)
}

func Test_calcAKEKeys(t *testing.T) {
	bob := AKE{
		akeContext: newAkeContext(otrV3{}, fixtureRand()),
	}

	bob.x = fixedx
	bob.gy = fixedgy

	key := bob.calcDHSharedSecret(true)
	bob.calcAKEKeys(key)

	assertEquals(t, hex.EncodeToString(bob.ssid[:]), "9cee5d2c7edbc86d")
	assertEquals(t, hex.EncodeToString(bob.revealKey.c[:]), "5745340b350364a02a0ac1467a318dcc")
	assertEquals(t, hex.EncodeToString(bob.sigKey.c[:]), "d942cc80b66503414c05e3752d9ba5c4")
	assertEquals(t, hex.EncodeToString(bob.revealKey.m1[:]), "d3251498fb9d977d07392a96eafb8c048d6bc67064bd7da72aa38f20f87a2e3d")
	assertEquals(t, hex.EncodeToString(bob.revealKey.m2[:]), "79c101a78a6c5819547a36b4813c84a8ac553d27a5d4b58be45dd0f3a67d3ca6")
	assertEquals(t, hex.EncodeToString(bob.sigKey.m1[:]), "b6254b8eab0ad98152949454d23c8c9b08e4e9cf423b27edc09b1975a76eb59c")
	assertEquals(t, hex.EncodeToString(bob.sigKey.m2[:]), "954be27015eeb0455250144d906e83e7d329c49581aea634c4189a3c981184f5")

	var alice AKE
	alice.y = fixedy
	alice.gx = fixedgx

	key = alice.calcDHSharedSecret(false)
	alice.calcAKEKeys(key)

	assertEquals(t, hex.EncodeToString(alice.ssid[:]), "9cee5d2c7edbc86d")
	assertEquals(t, hex.EncodeToString(alice.revealKey.c[:]), "5745340b350364a02a0ac1467a318dcc")
	assertEquals(t, hex.EncodeToString(alice.sigKey.c[:]), "d942cc80b66503414c05e3752d9ba5c4")
	assertEquals(t, hex.EncodeToString(alice.revealKey.m1[:]), "d3251498fb9d977d07392a96eafb8c048d6bc67064bd7da72aa38f20f87a2e3d")
	assertEquals(t, hex.EncodeToString(alice.revealKey.m2[:]), "79c101a78a6c5819547a36b4813c84a8ac553d27a5d4b58be45dd0f3a67d3ca6")
	assertEquals(t, hex.EncodeToString(alice.sigKey.m1[:]), "b6254b8eab0ad98152949454d23c8c9b08e4e9cf423b27edc09b1975a76eb59c")
	assertEquals(t, hex.EncodeToString(alice.sigKey.m2[:]), "954be27015eeb0455250144d906e83e7d329c49581aea634c4189a3c981184f5")
}

func Test_generateRevealKeyEncryptedSignature(t *testing.T) {
	rnd := fixedRand([]string{"cbcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd"})
	ake := AKE{
		akeContext: newAkeContext(otrV3{}, rnd),
	}

	ake.ourKey = bobPrivateKey
	ake.x = fixedx
	ake.gx = fixedgx
	ake.gy = fixedgy
	ake.ourKeyID = 1

	key := ake.calcDHSharedSecret(true)
	ake.calcAKEKeys(key)
	expectedEncryptedSignature, _ := hex.DecodeString("000001d2dda2d4ef365711c172dad92804b201fcd2fdd6444568ebf0844019fb65ca4f5f57031936f9a339e08bfd4410905ab86c5d6f73e6c94de6a207f373beff3f7676faee7b1d3be21e630fe42e95db9d4ac559252bff530481301b590e2163b99bde8aa1b07448bf7252588e317b0ba2fc52f85a72a921ba757785b949e5e682341d98800aa180aa0bd01f51180d48260e4358ffae72a97f652f02eb6ae3bc6a25a317d0ca5ed0164a992240baac8e043f848332d22c10a46d12c745dc7b1b0ee37fd14614d4b69d500b8ce562040e3a4bfdd1074e2312d3e3e4c68bd15d70166855d8141f695b21c98c6055a5edb9a233925cf492218342450b806e58b3a821e5d1d2b9c6b9cbcba263908d7190a3428ace92572c064a328f86fa5b8ad2a9c76d5b9dcaeae5327f545b973795f7c655248141c2f82db0a2045e95c1936b726d6474f50283289e92ab5c7297081a54b9e70fce87603506dedd6734bab3c1567ee483cd4bcb0e669d9d97866ca274f178841dafc2acfdcd10cb0e2d07db244ff4b1d23afe253831f142083d912a7164a3425f82c95675298cf3c5eb3e096bbc95e44ecffafbb585738723c0adbe11f16c311a6cddde630b9c304717ce5b09247d482f32709ea71ced16ba930a554f9949c1acbecf")
	expedctedMACSignature, _ := hex.DecodeString("8e6e5ef63a4e8d6aa2cfb1c5fe1831498862f69d7de32af4f9895180e4b494e6")

	encryptedSig, err := ake.generateEncryptedSignature(&ake.revealKey, true)
	macSig := sumHMAC(ake.revealKey.m2[:], encryptedSig)
	assertEquals(t, err, nil)
	assertDeepEquals(t, encryptedSig, expectedEncryptedSignature)
	assertDeepEquals(t, macSig, expedctedMACSignature)
}

func Test_generateSigKeyEncryptedSignature(t *testing.T) {
	rnd := fixedRand([]string{"bbcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd"})
	ake := AKE{
		akeContext: newAkeContext(otrV3{}, rnd),
	}

	ake.ourKey = alicePrivateKey
	ake.y = fixedy
	ake.gx = fixedgx
	ake.gy = fixedgy
	ake.ourKeyID = 1

	key := ake.calcDHSharedSecret(false)
	ake.calcAKEKeys(key)
	expectedEncryptedSignature, _ := hex.DecodeString("000001d2b4f6ac650cc1d28f61a3b9bdf3cd60e2d1ea55d4c56e9f954eb22e10764861fb40d69917f5c4249fa701f3c04fae9449cd13a5054861f95fbc5775fc3cfd931cf5cc1a89eac82e7209b607c4fbf18df945e23bd0e91365fcc6c5dac072703dd8e2287372107f6a2cbb9139f5e82108d4cbcc1c6cdfcc772014136e756338745e2210d42c6e3ec4e9cf87fa8ebd8190e00f3a54bec86ee06cb7664059bb0fa79529e9d2e563ffecc5561477b3ba6bbf4ac679624b6da69a85822ed5c6ceb56a98740b1002026c503c39badab13b5d5ec948bbb961f0c90e68894a1fb70645a8e21ffe6b78e2e4ee62a62c48bd54e3d27c1166d098791518b53a10c409b5e55d16555b721a7750b7084e8972540bf0f1d76602e9b5fd58f94ed2dbf69fafccef84fdca2f9d800346b2358a200db060d8cf1b984a5213d02f7c27e452ad1cd893b0a668aaf6733809c31a392fc6cfc754691aca9a51582b636b92ea10abd661dd88bfd4c5f19b3ce265951728637b23fff7f7c0638721b6a01b3f1c3e923c10ea37d4e240fd973647d34dde6991cc3a04ce459c23e3ee2a858912ff78f405bbd9951935a120017904537db50f6e9e29338938f2b45ed323fc508d02fd0a0703e53ffc1889bccdec87e7c3d87e442fe29a7654d1")
	expedctedMACSignature, _ := hex.DecodeString("66b47e29be91a7cf4803d731921482fd514b4a53a9dd1639b17705c90185f91d")

	encryptedSig, err := ake.generateEncryptedSignature(&ake.sigKey, false)
	macSig := sumHMAC(ake.sigKey.m2[:], encryptedSig)
	assertEquals(t, err, nil)
	assertDeepEquals(t, encryptedSig, expectedEncryptedSignature)
	assertDeepEquals(t, macSig, expedctedMACSignature)
}

func Test_generateVerifyData(t *testing.T) {
	var ake AKE
	ake.ourKey = bobPrivateKey
	ake.gx = fixedgx
	ake.gy = fixedgy
	ake.ourKeyID = 1

	verifyData := ake.generateVerifyData(true, &ake.ourKey.PublicKey, ake.ourKeyID)
	expectedVerifyData, _ := hex.DecodeString("000000c0075dfab5a1eab059052d0ad881c4938d52669630d61833a367155d67d03a457f619683d0fa829781e974fd24f6865e8128a9312a167b77326a87dea032fc31784d05b18b9cbafebe162ae9b5369f8b0c5911cf1be757f45f2a674be5126a714a6366c28086b3c7088911dcc4e5fb1481ad70a5237b8e4a6aff4954c2ca6df338b9f08691e4c0defe12689b37d4df30ddef2687f789fcf623c5d0cf6f09b7e5e69f481d5fd1b24a77636fb676e6d733d129eb93e81189340233044766a36eb07d000000c02cdacabb00e63d8949aa85f7e6a095b1ee81a60779e58f8938ff1a7ed1e651d954bd739162e699cc73b820728af53aae60a46d529620792ddf839c5d03d2d4e92137a535b27500e3b3d34d59d0cd460d1f386b5eb46a7404b15c1ef84840697d2d3d2405dcdda351014d24a8717f7b9c51f6c84de365fea634737ae18ba22253a8e15249d9beb2dded640c6c0d74e4f7e19161cf828ce3ffa9d425fb68c0fddcaa7cbe81a7a5c2c595cce69a255059d9e5c04b49fb15901c087e225da850ff27000000000080a5138eb3d3eb9c1d85716faecadb718f87d31aaed1157671d7fee7e488f95e8e0ba60ad449ec732710a7dec5190f7182af2e2f98312d98497221dff160fd68033dd4f3a33b7c078d0d9f66e26847e76ca7447d4bab35486045090572863d9e4454777f24d6706f63e02548dfec2d0a620af37bbc1d24f884708a212c343b480d00000014e9c58f0ea21a5e4dfd9f44b6a9f7f6a9961a8fa9000000803c4d111aebd62d3c50c2889d420a32cdf1e98b70affcc1fcf44d59cca2eb019f6b774ef88153fb9b9615441a5fe25ea2d11b74ce922ca0232bd81b3c0fcac2a95b20cb6e6c0c5c1ace2e26f65dc43c751af0edbb10d669890e8ab6beea91410b8b2187af1a8347627a06ecea7e0f772c28aae9461301e83884860c9b656c722f0000008065af8625a555ea0e008cd04743671a3cda21162e83af045725db2eb2bb52712708dc0cc1a84c08b3649b88a966974bde27d8612c2861792ec9f08786a246fcadd6d8d3a81a32287745f309238f47618c2bd7612cb8b02d940571e0f30b96420bcd462ff542901b46109b1e5ad6423744448d20a57818a8cbb1647d0fea3b664e00000001")

	assertDeepEquals(t, verifyData, expectedVerifyData)
}

func Test_processDHCommit_returnsErrorIfTheMessageIsNotLongEnoughForMessageHeader(t *testing.T) {
	ake := AKE{akeContext: newAkeContext(otrV2{}, fixtureRand())}
	err := ake.processDHCommit([]byte{0x01, 0x02})
	assertDeepEquals(t, err, errors.New("otr: invalid OTR message"))
}

func Test_processDHCommit_returnsErrorIfTheEncryptedGXPartIsNotCorrect(t *testing.T) {
	ake := AKE{akeContext: newAkeContext(otrV2{}, fixtureRand())}
	err := ake.processDHCommit([]byte{0x01, 0x02, 0x03, 0x00, 0x00, 0x00, 0x02, 0x01})
	assertDeepEquals(t, err, errors.New("otr: corrupt DH commit message"))
}

func Test_processDHCommit_returnsErrorIfTheHashedGXPartIsNotCorrect(t *testing.T) {
	ake := AKE{akeContext: newAkeContext(otrV2{}, fixtureRand())}
	err := ake.processDHCommit([]byte{0x01, 0x02, 0x03, 0x00, 0x00, 0x00, 0x01, 0x01, 0x00, 0x00, 0x00, 0x02, 0x01})
	assertDeepEquals(t, err, errors.New("otr: corrupt DH commit message"))
}

func Test_calcXBb_returnsErrorIfTheSigningDoesntWork(t *testing.T) {
	ake := AKE{akeContext: newAkeContext(otrV2{}, fixedRand([]string{"AB"}))}
	ake.ourKey = bobPrivateKey
	ake.ourKeyID = 1

	_, err := ake.calcXb(nil, []byte{0x00}, false)
	assertDeepEquals(t, err.Error(), "unexpected EOF")
}

func Test_dhCommitMessage_returnsErrorIfNoRandomnessIsAvailable(t *testing.T) {
	rnd := fixedRand([]string{"ABCD"})
	ake := AKE{akeContext: newAkeContext(otrV3{}, rnd)}
	_, err := ake.dhCommitMessage()
	assertDeepEquals(t, err, errors.New("otr: short read from random source"))
}

func Test_dhCommitMessage_returnsErrorIfNoRandomnessIsAvailableForR(t *testing.T) {
	rnd := fixedRand([]string{
		"ABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCD",
		"ABCDABCDABCDABCDABCDABCDABCDAB",
	})
	ake := AKE{akeContext: newAkeContext(otrV3{}, rnd)}
	_, err := ake.dhCommitMessage()
	assertDeepEquals(t, err, errors.New("otr: short read from random source"))
}

func Test_generateEncryptedSignature_returnsErrorIfCalcXbFails(t *testing.T) {
	rnd := fixedRand([]string{"abcd"})
	ake := AKE{akeContext: newAkeContext(otrV3{}, rnd)}

	ake.ourKey = bobPrivateKey
	ake.gx = fixedgx
	ake.gy = fixedgy

	_, err := ake.generateEncryptedSignature(&ake.revealKey, true)
	assertDeepEquals(t, err.Error(), "unexpected EOF")
}

func Test_revealSigMessage_returnsErrorFromGenerateEncryptedSignature(t *testing.T) {
	rnd := fixedRand([]string{"abcd"})
	ake := AKE{akeContext: newAkeContext(otrV3{}, rnd)}

	ake.ourKey = bobPrivateKey
	ake.y = fixedy
	ake.x = fixedx
	ake.gx = fixedgx
	ake.gy = fixedgy

	_, err := ake.revealSigMessage()
	assertDeepEquals(t, err.Error(), "unexpected EOF")
}

func Test_sigMessage_returnsErrorFromgenerateEncryptedSignature(t *testing.T) {
	rnd := fixedRand([]string{"cbcd"})
	ake := AKE{akeContext: newAkeContext(otrV3{}, rnd)}

	ake.ourKey = bobPrivateKey
	ake.y = fixedy
	ake.gx = fixedgx
	ake.gy = fixedgy
	ake.ourKeyID = 1
	_, err := ake.sigMessage()
	assertEquals(t, err.Error(), "unexpected EOF")
}

func Test_processDHKey_returnsErrorIfTheMessageIsNotLongEnoughForMessageHeader(t *testing.T) {
	ake := AKE{akeContext: newAkeContext(otrV2{}, fixedRand([]string{}))}
	_, err := ake.processDHKey([]byte{0x01, 0x02})
	assertDeepEquals(t, err, errors.New("otr: invalid OTR message"))
}

func Test_processDHKey_returnsErrorIfTheMessageHasAnIncorrectGyParameter(t *testing.T) {
	ake := AKE{akeContext: newAkeContext(otrV2{}, fixedRand([]string{}))}
	_, err := ake.processDHKey([]byte{0x01, 0x02, 0x03, 0x00, 0x00, 0x00, 0x02, 0x01})
	assertDeepEquals(t, err, errors.New("otr: corrupt DH key message"))
}

func Test_processDHKey_returnsErrorIfGyIsNotAValidDHParameter(t *testing.T) {
	ake := AKE{akeContext: newAkeContext(otrV2{}, fixedRand([]string{}))}
	_, err := ake.processDHKey([]byte{0x01, 0x02, 0x03, 0x00, 0x00, 0x00, 0x01, 0x01})
	assertDeepEquals(t, err, errors.New("otr: DH value out of range"))
}
