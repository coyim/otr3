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

func assertNil(t *testing.T, actual interface{}) {
	if actual != nil && !reflect.ValueOf(actual).IsNil() {
		t.Errorf("Expected:\n%#v \nto be nil\n", actual)
	}
}

func assertDeepEquals(t *testing.T, actual, expected interface{}) {
	if !reflect.DeepEqual(actual, expected) {
		t.Errorf("Expected:\n%#v \nto equal:\n%#v\n", actual, expected)
	}
}

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
		policies:         policies(p),
		fragmentSize:     65535, //we are not testing fragmentation by default
		ourInstanceTag:   0x101, //every conversation should be able to talk to each other
		theirInstanceTag: 0x101,
	}
}
