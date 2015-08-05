package otr3

import (
	"crypto/rand"
	"testing"
)

func Test_channelAganstRegularFunction(t *testing.T) {
	alice := &Conversation{Rand: rand.Reader}
	alice.Policies = policies(allowV2 | allowV3)
	alice.OurKey = alicePrivateKey

	bob := &Conversation{Rand: rand.Reader}
	bob.Policies = policies(allowV2 | allowV3)
	bob.OurKey = bobPrivateKey

	msg := alice.queryMessage()
	bob.initChannels()
	//Query
	_, msg = bob.ReceiveByChan(msg)
	//DHCommit
	_, toSend, err := alice.Receive(msg)
	assertEquals(t, err, nil)
	//DHKey
	_, msg = bob.ReceiveByChan(toSend[0])
	//RevealSig
	_, toSend, err = alice.Receive(msg)
	assertEquals(t, err, nil)
	//Sig
	_, msg = bob.ReceiveByChan(toSend[0])
	//FirstData
	plain1 := []byte("hello")
	toSend, _ = alice.Send(plain1)
	recPlain1, _ := bob.ReceiveByChan(toSend[0])
	//SecondData
	plain2 := []byte("world")
	toSend, _ = alice.Send(plain2)
	recPlain2, _ := bob.ReceiveByChan(toSend[0])

	assertDeepEquals(t, recPlain1, plain1)
	assertDeepEquals(t, recPlain2, plain2)
}

func (c *Conversation) ReceiveByChan(msg ValidMessage) (plain []byte, toSend ValidMessage) {
	c.receiveChan <- msg
	go c.serve()
	plain = <-c.plainChan
	toSend = <-c.toSendChan
	return
}

func (c *Conversation) SendByChan(msg ValidMessage) (plain []byte, toSend ValidMessage) {
	c.sendChan <- msg
	go c.serve()
	plain = <-c.plainChan
	toSend = <-c.toSendChan
	return
}
