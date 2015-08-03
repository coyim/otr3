package otr3

import "testing"

func Test_Authenticate_failsIfWeAreNotCurrentlyEncrypted(t *testing.T) {
	c := newConversation(otrV3{}, fixtureRand())
	c.msgState = plainText

	_, e := c.Authenticate([]byte("hello world"))
	assertEquals(t, e, errCantAuthenticateWithoutEncryption)
}

func Test_Authenticate_generatesAnSMPSecretFromTheSharedSecret(t *testing.T) {
	c := bobContextAfterAKE()
	c.msgState = encrypted
	c.ssid = [8]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
	c.OurKey = alicePrivateKey
	c.TheirKey = &bobPrivateKey.PublicKey

	_, e := c.Authenticate([]byte("hello world"))
	assertEquals(t, e, nil)
	assertDeepEquals(t, c.smp.secret, bnFromHex("3D7264BD983B8CA53CB365444844816F7D2453580B552EEE45CD09CA13614A5"))
}

func Test_Authenticate_generatesAndReturnsTheFirstSMPMessageToSend(t *testing.T) {
	c := bobContextAfterAKE()
	c.msgState = encrypted
	c.ssid = [8]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
	c.OurKey = bobPrivateKey
	c.TheirKey = &alicePrivateKey.PublicKey

	msg, e := c.Authenticate([]byte("hello world"))
	assertEquals(t, e, nil)
	assertEquals(t, isEncoded(msg[0]), true)
	dec, _ := c.decode(msg[0])
	_, messageBody, _ := c.parseMessageHeader(dec)
	assertDeepEquals(t, len(messageBody), 1361)
}

func Test_Authenticate_generatesAndSetsTheFirstMessageOnTheConversation(t *testing.T) {
	c := bobContextAfterAKE()
	c.msgState = encrypted
	c.ssid = [8]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
	c.OurKey = bobPrivateKey
	c.TheirKey = &alicePrivateKey.PublicKey
	c.smp.s1 = nil

	c.Authenticate([]byte("hello world"))

	assertNotNil(t, c.smp.s1)
}
