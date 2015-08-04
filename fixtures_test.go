package otr3

import (
	"crypto/rand"
	"io"
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
	c.keys.ourCurrentDHKeys.pub = fixedgx
	c.keys.ourPreviousDHKeys.priv = fixedx
	c.keys.ourPreviousDHKeys.pub = fixedgx

	c.keys.theirKeyID = 1
	c.keys.theirCurrentDHPubKey = fixedgy

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
	c.ake.theirPublicValue = fixedgy // stored at receiveDHKey

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

	copy(c.ake.r[:], fixedr)    // stored at sendDHCommit
	c.setSecretExponent(fixedx) // stored at sendDHCommit

	return c
}

func aliceContextAtReceiveRevealSig() *Conversation {
	c := aliceContextAtAwaitingRevealSig()
	c.ake.theirPublicValue = fixedgx // Alice decrypts encryptedGx using r

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

	c.setSecretExponent(fixedy) //stored at sendDHKey

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
			priv: fixedy,
			pub:  fixedgy,
		},
		ourPreviousDHKeys: dhKeyPair{
			priv: fixedy,
			pub:  fixedgy,
		},
		theirCurrentDHPubKey:  fixedgx,
		theirPreviousDHPubKey: fixedgx,
	}

	keys := calculateDHSessionKeys(fixedx, fixedgx, fixedgy)

	h, _ := conv.messageHeader(msgTypeData)
	m := dataMsg{
		senderKeyID:    senderKeyID,
		recipientKeyID: recipientKeyID,

		y:          fixedgy, //this is alices current Pub
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
	c := newConversation(otrV3{}, rand.Reader)

	header, withoutHeader, err := c.parseMessageHeader(encryptedDataMsg)
	if err != nil {
		panic(err)
	}

	m := dataMsg{}
	err = m.deserialize(withoutHeader)
	if err != nil {
		panic(err)
	}

	keys := calculateDHSessionKeys(fixedx, fixedgx, fixedgy)

	exp := plainDataMsg{}
	err = m.checkSign(keys.receivingMACKey, header)
	if err != nil {
		panic(err)
	}

	exp.decrypt(keys.receivingAESKey, m.topHalfCtr, m.encryptedMsg)

	return exp
}
