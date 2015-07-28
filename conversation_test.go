package otr3

import "testing"

func Test_receive_OTRQueryMsgRepliesWithDHCommitMessage(t *testing.T) {
	msg := []byte("?OTRv3?")
	c := newConversation(nil, fixtureRand())
	c.policies.add(allowV3)

	exp := []byte{
		0x00, 0x03, // protocol version
		msgTypeDHCommit,
	}

	toSend, err := c.receive(msg)

	assertEquals(t, err, nil)
	assertDeepEquals(t, toSend[:3], exp)
}

func Test_receive_OTRQueryMsgChangesContextProtocolVersion(t *testing.T) {
	msg := []byte("?OTRv3?")
	cxt := newConversation(nil, fixtureRand())
	cxt.policies.add(allowV3)

	cxt.receive(msg)

	assertDeepEquals(t, cxt.version, otrV3{})
}

func Test_receiveVerifiesMessageProtocolVersion(t *testing.T) {
	// protocol version
	msg := []byte{0x00, 0x02}
	c := newConversation(otrV3{}, fixtureRand())

	_, err := c.receive(msg)

	assertEquals(t, err, errWrongProtocolVersion)
}

func Test_receive_returnsAnErrorForAnInvalidOTRMessageWithoutVersionData(t *testing.T) {
	msg := []byte{0x00}
	c := newConversation(otrV3{}, fixtureRand())

	_, err := c.receive(msg)

	assertEquals(t, err, errInvalidOTRMessage)
}

func Test_receive_returnsAnErrorForADataMessageWhenNoEncryptionIsActive(t *testing.T) {
	m := []byte{
		0x00, 0x03, // protocol version
		msgTypeData,
	}
	c := newConversation(otrV3{}, fixtureRand())

	_, err := c.receive(m)
	assertDeepEquals(t, err, errEncryptedMessageWithNoSecureChannel)
}

func Test_receive_returnsAnErrorForAnIncorrectTLVMessage(t *testing.T) {
	m := []byte{
		0x00, 0x03, // protocol version
		msgTypeData,
		0x99,
	}
	c := newConversation(otrV3{}, fixtureRand())
	c.msgState = encrypted
	_, err := c.receive(m)
	assertDeepEquals(t, err, newOtrError("corrupt data message"))
}

func Test_receive_DHCommitMessageReturnsDHKeyForOTR3(t *testing.T) {
	exp := []byte{
		0x00, 0x03, // protocol version
		msgTypeDHKey,
	}

	dhCommitAKE := fixtureConversation()
	dhCommitMsg, _ := dhCommitAKE.dhCommitMessage()

	c := newConversation(otrV3{}, fixtureRand())
	c.policies.add(allowV3)

	dhKeyMsg, err := c.receive(dhCommitMsg)

	assertEquals(t, err, nil)
	assertDeepEquals(t, dhKeyMsg[:lenMsgHeader], exp)
}

func Test_receive_DHKeyMessageReturnsRevealSignature(t *testing.T) {
	v := otrV3{}

	msg := fixtureDHKeyMsg(v)
	c := bobContextAtAwaitingDHKey()

	toSend, err := c.receive(msg)

	assertEquals(t, err, nil)
	assertDeepEquals(t, dhMsgType(toSend), msgTypeRevealSig)
}

func Test_randMPI_returnsNotOKForAShortRead(t *testing.T) {
	c := newConversation(otrV3{}, fixedRand([]string{"ABCD"}))
	var buf [3]byte

	_, ok := c.randMPI(buf[:])
	assertEquals(t, ok, false)
}

func Test_randMPI_returnsOKForARealRead(t *testing.T) {
	c := newConversation(otrV3{}, fixedRand([]string{"ABCD"}))
	var buf [2]byte

	_, ok := c.randMPI(buf[:])
	assertEquals(t, ok, true)
}

func Test_genDataMsg_withKeyExchangeData(t *testing.T) {
	c := bobContextAfterAKE()
	c.keys.ourKeyID = 2
	c.keys.theirKeyID = 3
	c.keys.ourCounter = 0x1011121314

	dataMsg := c.genDataMsg(nil)

	assertEquals(t, dataMsg.senderKeyID, uint32(1))
	assertEquals(t, dataMsg.recipientKeyID, uint32(3))
	assertDeepEquals(t, dataMsg.y, c.keys.ourCurrentDHKeys.pub)
	assertDeepEquals(t, dataMsg.topHalfCtr, [8]byte{
		0x00, 0x00, 0x00, 0x10, 0x11, 0x12, 0x13, 0x14,
	})
	assertEquals(t, c.keys.ourCounter, uint64(0x1011121314+1))
}

func Test_genDataMsg_hasEncryptedMessage(t *testing.T) {
	c := bobContextAfterAKE()

	expected := bytesFromHex("4f0de18011633ed0264ccc1840d64f4cf8f0c91ef78890ab82edef36cb38210bb80760585ff43d736a9ff3e4bb05fc088fa34c2f21012988d539ebc839e9bc97633f4c42de15ea5c3c55a2b9940ca35015ded14205b9df78f936cb1521aedbea98df7dc03c116570ba8d034abc8e2d23185d2ce225845f38c08cb2aae192d66d601c1bc86149c98e8874705ae365b31cda76d274429de5e07b93f0ff29152716980a63c31b7bda150b222ba1d373f786d5f59f580d4f690a71d7fc620e0a3b05d692221ddeebac98d6ed16272e7c4596de27fb104ad747aa9a3ad9d3bc4f988af0beb21760df06047e267af0109baceb0f363bcaff7b205f2c42b3cb67a942f2")
	dataMsg := c.genDataMsg([]byte("we are awesome"))

	assertDeepEquals(t, dataMsg.encryptedMsg, expected)
}

func Test_genDataMsg_revealOldMACKeysFromKeyManagementContext(t *testing.T) {
	oldMACKeys := []macKey{
		macKey{0x00, 0x01, 0x02, 0x03, 0x00, 0x01, 0x02, 0x03, 0x00, 0x01, 0x02, 0x03, 0x00, 0x01, 0x02, 0x03, 0x00, 0x01, 0x02, 0x03},
		macKey{0x01, 0x01, 0x02, 0x03, 0x00, 0x01, 0x02, 0x03, 0x00, 0x01, 0x02, 0x03, 0x00, 0x01, 0x02, 0x03, 0x00, 0x01, 0x02, 0x03},
	}

	c := bobContextAfterAKE()
	c.keys.oldMACKeys = oldMACKeys

	dataMsg := c.genDataMsg(nil)

	assertDeepEquals(t, dataMsg.oldMACKeys, oldMACKeys)
}

func Test_processDataMessage_deserializeAndDecryptDataMsg(t *testing.T) {
	datamsg := bytesFromHex("0003030000010100000101000000000100000001000000c03a3ca02c03bef84c7596504b7b2dee2820500bf51107e4447cfd2fddd8132a29668ef7cb3f56ff75f80e9d5a3c34e4aaa45a63beee83c058d21653e45d56ad04f6493545ad5bc3441f9a1a23fdf5ea0d812f3dfa02de9742ee9b1779dd1d84bf1bf06700a05779ff1a730c51ecdce34d251317dacdcbe865f12c2bf8e4a8a15cc10975184a7509e3f82244c8594d3df18b411648dc059cf341c50ab0d3981f186519ca3104609e89a5f4be44047068c5ba33d2b1de0e9b7d5e6aa67c148f57d70000000000000001000001007104b8684860d2eacc0d653ca9696171f5d7b03d90a06fd46305c041ab4af8313826ca82f8fc43c755c56dd62fa025822e72d9566a32fe88f189e0fb1b07128a37db49350392470cdd57f280f565ab775d58af6f5d8efca39126192efefe1f98bdfd2135b1c6ce8e68d8d3bfd50eae34187191524492193d20dd75d6b04a1e7d90fe1e71a9843b720df310119c1db82928c11308d93ed508641e73b6d579eefbcb432ab2ebf2b15a3b1c8baca86d5008c81286705b9368abec0d5cf4b6e2289be1040b5ac172cbc81f7a594d721cafd50e7cfdc2616c6d59cf445f885d8e80980a73f6a55a34be9e90b7ec25f757e212fa2b79c4c56d922a804168bfeca75199dbede31d8101018586d1f992afdd80117cf84d1000000000")
	bob := newConversation(otrV3{}, nil)
	bob.policies.add(allowV2)
	bob.policies.add(allowV3)
	bob.ourKey = bobPrivateKey
	bob.theirKey = &alicePrivateKey.PublicKey
	bob.keys.ourKeyID = 2
	bob.keys.theirKeyID = 1
	bob.keys.ourPreviousDHKeys.priv = bnFromHex("28cea443a1ddeae5c39fd9061a429243eeb52f9f963dcb483a77ec9ed201f8eb3e898fb645657f27")
	bob.keys.ourPreviousDHKeys.pub = bnFromHex("e291f2e06da00d59c9666d80d6c511a0bd9ae54d916b65db7e72f70904ae05d55259df42fb7b29d11babf11e78cd584d0f137ca1187b4f920e0fbef85c0e5f4b55bf907ea6e119dcfa7e339e72d6b52e874dc46afedd9290360659928ad30f504dad43160946dbd9de7748d18417c223790e528a6f13bf25285318416ccfed0bceafbca70dce832ca8216a654c49ac29dc6af098e7e2744a1dfaf7d2643eb1b3787c4c1db4f649096c3241f69165f965a290651304e23fd2422dae180796d52f")
	bob.keys.theirCurrentDHPubKey = bnFromHex("da61b77be39426456fecfd6df16645bd2c967bc1a27b165dbf77fea4753ece7a8b938532395bbd1def2890a2792f1854c2d736ee27139356b3bb2583afa4c96a9083209d9f2bb1caeb6fe5ee608715ae6dc1c470e38b895e48e0532af5388c8e591d9ebe361f118ad54d8640f24fa54fdb1d07594d496150554094e5ec4bcfcc6b1b4b058b679824306ad7ae481a25d0758cc01c29c281ce33ac2f58d6eaa99985f855e9ce667ff287b4d27d7c73a7717277546d17e8dd5539861bc26fa04c1b")
	plain, tlvs, err := bob.processDataMessage(datamsg)

	assertDeepEquals(t, err, nil)
	assertDeepEquals(t, plain, []byte("hello"))
	padding := paddingGranularity - ((len(plain) + tlvHeaderLen + nulByteLen) % paddingGranularity)
	assertDeepEquals(t, tlvs, []tlv{tlv{tlvType: 0, tlvLength: uint16(padding), tlvValue: make([]byte, padding)}})
}

func Test_processDataMessage_returnErrorWhenOurKeyIDUnexpected(t *testing.T) {
	datamsg := bytesFromHex("0003030000010100000101000000000100000001000000c03a3ca02c03bef84c7596504b7b2dee2820500bf51107e4447cfd2fddd8132a29668ef7cb3f56ff75f80e9d5a3c34e4aaa45a63beee83c058d21653e45d56ad04f6493545ad5bc3441f9a1a23fdf5ea0d812f3dfa02de9742ee9b1779dd1d84bf1bf06700a05779ff1a730c51ecdce34d251317dacdcbe865f12c2bf8e4a8a15cc10975184a7509e3f82244c8594d3df18b411648dc059cf341c50ab0d3981f186519ca3104609e89a5f4be44047068c5ba33d2b1de0e9b7d5e6aa67c148f57d70000000000000001000001007104b8684860d2eacc0d653ca9696171f5d7b03d90a06fd46305c041ab4af8313826ca82f8fc43c755c56dd62fa025822e72d9566a32fe88f189e0fb1b07128a37db49350392470cdd57f280f565ab775d58af6f5d8efca39126192efefe1f98bdfd2135b1c6ce8e68d8d3bfd50eae34187191524492193d20dd75d6b04a1e7d90fe1e71a9843b720df310119c1db82928c11308d93ed508641e73b6d579eefbcb432ab2ebf2b15a3b1c8baca86d5008c81286705b9368abec0d5cf4b6e2289be1040b5ac172cbc81f7a594d721cafd50e7cfdc2616c6d59cf445f885d8e80980a73f6a55a34be9e90b7ec25f757e212fa2b79c4c56d922a804168bfeca75199dbede31d8101018586d1f992afdd80117cf84d1000000000")
	bob := newConversation(otrV3{}, nil)
	bob.policies.add(allowV2)
	bob.policies.add(allowV3)
	bob.ourKey = bobPrivateKey
	bob.theirKey = &alicePrivateKey.PublicKey
	bob.keys.ourKeyID = 3
	bob.keys.theirKeyID = 1
	bob.keys.ourPreviousDHKeys.priv = bnFromHex("28cea443a1ddeae5c39fd9061a429243eeb52f9f963dcb483a77ec9ed201f8eb3e898fb645657f27")
	bob.keys.ourPreviousDHKeys.pub = bnFromHex("e291f2e06da00d59c9666d80d6c511a0bd9ae54d916b65db7e72f70904ae05d55259df42fb7b29d11babf11e78cd584d0f137ca1187b4f920e0fbef85c0e5f4b55bf907ea6e119dcfa7e339e72d6b52e874dc46afedd9290360659928ad30f504dad43160946dbd9de7748d18417c223790e528a6f13bf25285318416ccfed0bceafbca70dce832ca8216a654c49ac29dc6af098e7e2744a1dfaf7d2643eb1b3787c4c1db4f649096c3241f69165f965a290651304e23fd2422dae180796d52f")
	bob.keys.theirCurrentDHPubKey = bnFromHex("da61b77be39426456fecfd6df16645bd2c967bc1a27b165dbf77fea4753ece7a8b938532395bbd1def2890a2792f1854c2d736ee27139356b3bb2583afa4c96a9083209d9f2bb1caeb6fe5ee608715ae6dc1c470e38b895e48e0532af5388c8e591d9ebe361f118ad54d8640f24fa54fdb1d07594d496150554094e5ec4bcfcc6b1b4b058b679824306ad7ae481a25d0758cc01c29c281ce33ac2f58d6eaa99985f855e9ce667ff287b4d27d7c73a7717277546d17e8dd5539861bc26fa04c1b")
	_, _, err := bob.processDataMessage(datamsg)

	assertDeepEquals(t, err.Error(), "otr: unexpected ourKeyID 1")
}

func Test_OTRisDisabledIfNoVersionIsAllowedInThePolicy(t *testing.T) {
	var nilB []byte
	msg := []byte("?OTRv3?")

	c := newConversation(nil, fixtureRand())

	s := c.send(msg)
	assertDeepEquals(t, s, msg)

	r, err := c.receive(msg)
	assertEquals(t, err, nil)
	assertDeepEquals(t, r, nilB)
}
