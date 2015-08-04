package otr3

import (
	"encoding/hex"
	"io"
	"math/big"
	"reflect"
	"testing"
)

func assertEquals(t *testing.T, actual, expected interface{}) {
	if actual != expected {
		t.Errorf("Expected:\n%#v \nto equal:\n%#v\n", actual, expected)
	}
}

func assertFuncEquals(t *testing.T, actual, expected interface{}) {
	f1 := reflect.ValueOf(actual)
	f2 := reflect.ValueOf(expected)
	if f1.Pointer() != f2.Pointer() {
		t.Errorf("Expected:\n%#v \nto equal:\n%#v\n", actual, expected)
	}
}

func assertNil(t *testing.T, actual interface{}) {
	if actual != nil && !reflect.ValueOf(actual).IsNil() {
		t.Errorf("Expected:\n%#v \nto be nil\n", actual)
	}
}

func assertNotNil(t *testing.T, actual interface{}) {
	if actual == nil || reflect.ValueOf(actual).IsNil() {
		t.Errorf("Expected:\n%#v \nto not be nil\n", actual)
	}
}

func assertDeepEquals(t *testing.T, actual, expected interface{}) {
	if !reflect.DeepEqual(actual, expected) {
		t.Errorf("Expected:\n%#v \nto equal:\n%#v\n", actual, expected)
	}
}

func dhMsgType(msg []byte) byte {
	return msg[2]
}

func dhMsgVersion(msg []byte) uint16 {
	_, protocolVersion, _ := extractShort(msg)
	return protocolVersion
}

func bytesFromHex(s string) []byte {
	val, _ := hex.DecodeString(s)
	return val
}

// bnFromHex is a test utility that doesn't take into account possible errors. Thus, make sure to only call it with valid hexadecimal strings (of even length)
func bnFromHex(s string) *big.Int {
	res, _ := new(big.Int).SetString(s, 16)
	return res
}

// parseIntoPrivateKey is a test utility that doesn't take into account possible errors. Thus, make sure to only call it with valid values
func parseIntoPrivateKey(hexString string) *PrivateKey {
	b, _ := hex.DecodeString(hexString)
	var pk PrivateKey
	pk.Parse(b)
	return &pk
}

func newConversation(v otrVersion, rand io.Reader) *Conversation {
	var p policy
	switch v {
	case otrV3{}:
		p = allowV3
	case otrV2{}:
		p = allowV2
	}
	akeNotStarted := new(ake)
	akeNotStarted.state = authStateNone{}

	return &Conversation{
		version: v,
		Rand:    rand,
		smp: smp{
			state: smpStateExpect1{},
		},
		ake:              akeNotStarted,
		Policies:         policies(p),
		fragmentSize:     65535, //we are not testing fragmentation by default
		ourInstanceTag:   0x101, //every conversation should be able to talk to each other
		theirInstanceTag: 0x101,
	}
}

func (c *Conversation) expectMessageEvent(t *testing.T, f func(), expectedEvent MessageEvent, expectedMessage string, expectedError error) {
	called := false

	c.getEventHandler().handleMessageEvent = func(event MessageEvent, message string, err error) {
		assertDeepEquals(t, event, expectedEvent)
		assertDeepEquals(t, message, expectedMessage)
		assertDeepEquals(t, err, expectedError)
		called = true
	}

	f()

	assertEquals(t, called, true)
}
