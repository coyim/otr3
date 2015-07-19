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
		t.Errorf("Expected:\n%v \nto equal:\n%v\n", actual, expected)
	}
}

func assertDeepEquals(t *testing.T, actual, expected interface{}) {
	if !reflect.DeepEqual(actual, expected) {
		t.Errorf("Expected:\n%v \nto equal:\n%v\n", actual, expected)
	}
}

func hexToByte(s string) []byte {
	plainBytes, _ := hex.DecodeString(s)
	return plainBytes
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
		plainBytes := hexToByte(frr.data[frr.at])
		frr.at++
		n = copy(p, plainBytes)
		return
	}
	return 0, io.EOF
}

// bnFromHex is a test utility that doesn't take into account possible errors. Thus, make sure to only call it with valid hexadecimal strings (of even length)
func bnFromHex(s string) *big.Int {
	res, _ := new(big.Int).SetString(s, 16)
	return res
}
