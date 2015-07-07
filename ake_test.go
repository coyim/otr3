package otr3

import (
	"encoding/hex"
	"testing"
)

var r = [16]byte{
	0x00, 0x01, 0x02, 0x03,
	0x00, 0x01, 0x02, 0x03,
	0x00, 0x01, 0x02, 0x03,
	0x00, 0x01, 0x02, 0x03,
}
var x = [40]byte{
	0x00, 0x01, 0x02, 0x03,
	0x00, 0x01, 0x02, 0x03,
	0x00, 0x01, 0x02, 0x03,
	0x00, 0x01, 0x02, 0x03,
	0x00, 0x01, 0x02, 0x03,
	0x00, 0x01, 0x02, 0x03,
	0x00, 0x01, 0x02, 0x03,
	0x00, 0x01, 0x02, 0x03,
	0x00, 0x01, 0x02, 0x03,
	0x00, 0x01, 0x02, 0x03,
}

func TestDHCommitMessage(t *testing.T) {
	protocolVersion := [2]byte{}
	messageType := 0x01
	sendInstag := 0x0001
	receiveInstag := 0x0001
	var ake AKE
	ake.Rand = fixedRand([]string{hex.EncodeToString(x[:]), hex.EncodeToString(r[:])})
	ake.initGx()
	t.Skipf("protocolVersion %x", protocolVersion)
	t.Skipf("messageType %x", messageType)
	t.Skipf("sendInstag %x", sendInstag)
	t.Skipf("receiveInstag %x", receiveInstag)
}

func TestEncryptGx(t *testing.T) {
	var ake AKE
	ake.Rand = fixedRand([]string{hex.EncodeToString(x[:]), hex.EncodeToString(r[:])})
	ake.initGx()
	encryptGx := ake.encryptGx()
	assertEquals(t, len(encryptGx), len(BytesToMPI(ake.gx.Bytes())))
}

func TestHashedGx(t *testing.T) {
	var ake AKE
	ake.Rand = fixedRand([]string{hex.EncodeToString(x[:])})
	ake.initGx()
	hashedGx := ake.hashedGx()
	assertEquals(t, hex.EncodeToString(hashedGx[:]), "d0a4c6efc6fd45398e67fc9166c2097b801727a19c47a7700437abad3e9eaebf")
}
