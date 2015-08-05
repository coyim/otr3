package otr3

import (
	"crypto/rand"
	"io"
	"math/big"
)

type fixedRandReader struct {
	data []string
	at   int
}

func fixedRand(data []string) io.Reader {
	return &fixedRandReader{data, 0}
}

func (frr *fixedRandReader) Read(p []byte) (n int, err error) {
	if frr.at < len(frr.data) {
		plainBytes := bytesFromHex(frr.data[frr.at])
		frr.at++
		n = copy(p, plainBytes)
		return
	}
	return 0, io.EOF
}

func fixtureConversation() *Conversation {
	return fixtureConversationWithVersion(otrV3{})
}

func fixtureConversationV2() *Conversation {
	return fixtureConversationWithVersion(otrV2{})
}

func fixtureConversationWithVersion(v otrVersion) *Conversation {
	return newConversation(v, fixtureRand())
}

func fixtureDHCommitMsg() []byte {
	c := fixtureConversation()
	c.theirInstanceTag = 0
	msg, _ := c.dhCommitMessage()
	msg, _ = c.wrapMessageHeader(msgTypeDHCommit, msg)
	return msg
}

func fixtureDHCommitMsgBody() []byte {
	return fixtureDHCommitMsg()[otrv3HeaderLen:]
}

func fixtureDHCommitMsgV2() []byte {
	c := fixtureConversationV2()
	msg, _ := c.dhCommitMessage()
	msg, _ = c.wrapMessageHeader(msgTypeDHCommit, msg)
	return msg
}

func fixtureDHKeyMsg(v otrVersion) []byte {
	c := fixtureConversationWithVersion(v)
	c.OurKey = alicePrivateKey
	msg, _ := c.dhKeyMessage()
	msg, _ = c.wrapMessageHeader(msgTypeDHKey, msg)
	return msg
}

func headLen(v otrVersion) int {
	val := otrV2{}
	if val == v {
		return otrv2HeaderLen
	}
	return otrv3HeaderLen
}

func fixtureDHKeyMsgBody(v otrVersion) []byte {
	return fixtureDHKeyMsg(v)[headLen(v):]
}

func fixtureRevealSigMsg(v otrVersion) []byte {
	c := bobContextAtReceiveDHKey()
	c.version = v

	msg, _ := c.revealSigMessage()
	msg, _ = c.wrapMessageHeader(msgTypeRevealSig, msg)

	return msg
}

func fixtureRevealSigMsgBody(v otrVersion) []byte {
	return fixtureRevealSigMsg(v)[headLen(v):]
}

func fixtureSigMsg(v otrVersion) []byte {
	c := aliceContextAtReceiveRevealSig()
	c.version = v

	msg, _ := c.sigMessage()
	msg, _ = c.wrapMessageHeader(msgTypeSig, msg)

	return msg
}

func bobContextAfterAKE() *Conversation {
	c := newConversation(otrV3{}, fixtureRand())
	c.keys.ourKeyID = 1
	c.keys.ourCurrentDHKeys.pub = fixedGX()
	c.keys.ourPreviousDHKeys.priv = fixedX()
	c.keys.ourPreviousDHKeys.pub = fixedGX()

	c.keys.theirKeyID = 1
	c.keys.theirCurrentDHPubKey = fixedGY()

	//TODO ourKeyID must be greater than 0
	// Temp fix for 2 because when we call genDataMsg, we are sending ourKeyID-1
	c.keys.ourKeyID = 2

	return c
}

func bobContextAtAwaitingSig() *Conversation {
	c := bobContextAtReceiveDHKey()
	c.version = otrV2{}
	c.Policies.add(allowV2)
	c.ake.state = authStateAwaitingSig{}

	return c
}

func bobContextAtReceiveDHKey() *Conversation {
	c := bobContextAtAwaitingDHKey()
	c.ake.theirPublicValue = fixedGY() // stored at receiveDHKey

	copy(c.ake.sigKey.c[:], bytesFromHex("d942cc80b66503414c05e3752d9ba5c4"))
	copy(c.ake.sigKey.m1[:], bytesFromHex("b6254b8eab0ad98152949454d23c8c9b08e4e9cf423b27edc09b1975a76eb59c"))
	copy(c.ake.sigKey.m2[:], bytesFromHex("954be27015eeb0455250144d906e83e7d329c49581aea634c4189a3c981184f5"))

	return c
}

func bobContextAtAwaitingDHKey() *Conversation {
	c := newConversation(otrV3{}, fixtureRand())
	c.initAKE()
	c.Policies.add(allowV3)
	c.ake.state = authStateAwaitingDHKey{}
	c.OurKey = bobPrivateKey

	copy(c.ake.r[:], fixedr)      // stored at sendDHCommit
	c.setSecretExponent(fixedX()) // stored at sendDHCommit

	return c
}

func aliceContextAtReceiveRevealSig() *Conversation {
	c := aliceContextAtAwaitingRevealSig()
	c.ake.theirPublicValue = fixedGX() // Alice decrypts encryptedGx using r

	return c
}

func aliceContextAtAwaitingDHCommit() *Conversation {
	c := newConversation(otrV2{}, fixtureRand())
	c.initAKE()
	c.Policies.add(allowV2)
	c.ake.state = authStateNone{}
	c.OurKey = alicePrivateKey
	return c
}

func aliceContextAtAwaitingRevealSig() *Conversation {
	c := newConversation(otrV2{}, fixtureRand())
	c.initAKE()
	c.Policies.add(allowV2)
	c.ake.state = authStateAwaitingRevealSig{}
	c.OurKey = alicePrivateKey

	copy(c.ake.hashedGx[:], expectedHashedGxValue) //stored at receiveDHCommit
	c.ake.encryptedGx = expectedEncryptedGxValue   //stored at receiveDHCommit

	c.setSecretExponent(fixedY()) //stored at sendDHKey

	return c
}

//Alice generates a encrypted message to Bob
//Fixture data msg never rotates the receiver keys when the returned context is
//used before receiving the message
func fixtureDataMsg(plain plainDataMsg) ([]byte, keyManagementContext) {
	var senderKeyID uint32 = 1
	var recipientKeyID uint32 = 1
	conv := newConversation(otrV3{}, rand.Reader)
	//We use a combination of ourKeyId, theirKeyID, senderKeyID and recipientKeyID
	//to make sure both sender and receiver will use the same DH session keys
	receiverContext := keyManagementContext{
		ourCounter:   1,
		theirCounter: 1,

		ourKeyID:   senderKeyID + 1,
		theirKeyID: recipientKeyID + 1,
		ourCurrentDHKeys: dhKeyPair{
			priv: fixedY(),
			pub:  fixedGY(),
		},
		ourPreviousDHKeys: dhKeyPair{
			priv: fixedY(),
			pub:  fixedGY(),
		},
		theirCurrentDHPubKey:  fixedGX(),
		theirPreviousDHPubKey: fixedGX(),
	}

	keys := calculateDHSessionKeys(fixedX(), fixedGX(), fixedGY())

	h, _ := conv.messageHeader(msgTypeData)
	m := dataMsg{
		senderKeyID:    senderKeyID,
		recipientKeyID: recipientKeyID,

		y:          fixedGY(), //this is alices current Pub
		topHalfCtr: [8]byte{0, 0, 0, 0, 0, 0, 0, 2},
	}
	m.encryptedMsg = plain.encrypt(keys.sendingAESKey, m.topHalfCtr)
	m.sign(keys.sendingMACKey, h)
	msg := append(h, m.serialize()...)

	return msg, receiverContext
}

//Alice decrypts a encrypted message from Bob, generated after receiving
//an encrypted message from Alice generated with fixtureDataMsg()
func fixtureDecryptDataMsg(encryptedDataMsg []byte) plainDataMsg {
	_, pd, e := fixtureDecryptDataMsgBase(encryptedDataMsg)
	if e != nil {
		panic(e)
	}
	return pd
}

func fixtureDecryptDataMsgBase(encryptedDataMsg []byte) ([]byte, plainDataMsg, error) {
	c := newConversation(otrV3{}, rand.Reader)

	header, withoutHeader, err := c.parseMessageHeader(encryptedDataMsg)
	if err != nil {
		return nil, plainDataMsg{}, err
	}

	m := dataMsg{}
	err = m.deserialize(withoutHeader)
	if err != nil {
		return nil, plainDataMsg{}, err
	}

	keys := calculateDHSessionKeys(fixedX(), fixedGX(), fixedGY())

	exp := plainDataMsg{}
	err = m.checkSign(keys.receivingMACKey, header)
	if err != nil {
		return nil, plainDataMsg{}, err
	}

	exp.decrypt(keys.receivingAESKey, m.topHalfCtr, m.encryptedMsg)

	return header, exp, nil
}

func fixedX() *big.Int {
	return bnFromHex("bbcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd")
}

func fixedY() *big.Int {
	return bnFromHex("abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd")
}

func fixedGX() *big.Int {
	return bnFromHex("75dfab5a1eab059052d0ad881c4938d52669630d61833a367155d67d03a457f619683d0fa829781e974fd24f6865e8128a9312a167b77326a87dea032fc31784d05b18b9cbafebe162ae9b5369f8b0c5911cf1be757f45f2a674be5126a714a6366c28086b3c7088911dcc4e5fb1481ad70a5237b8e4a6aff4954c2ca6df338b9f08691e4c0defe12689b37d4df30ddef2687f789fcf623c5d0cf6f09b7e5e69f481d5fd1b24a77636fb676e6d733d129eb93e81189340233044766a36eb07d")
}

func fixedGY() *big.Int {
	return bnFromHex("2cdacabb00e63d8949aa85f7e6a095b1ee81a60779e58f8938ff1a7ed1e651d954bd739162e699cc73b820728af53aae60a46d529620792ddf839c5d03d2d4e92137a535b27500e3b3d34d59d0cd460d1f386b5eb46a7404b15c1ef84840697d2d3d2405dcdda351014d24a8717f7b9c51f6c84de365fea634737ae18ba22253a8e15249d9beb2dded640c6c0d74e4f7e19161cf828ce3ffa9d425fb68c0fddcaa7cbe81a7a5c2c595cce69a255059d9e5c04b49fb15901c087e225da850ff27")
}
