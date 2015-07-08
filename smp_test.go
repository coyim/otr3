package otr3

import "testing"

func Test_generateSMPSecretGeneratesASecret(t *testing.T) {
	aliceFingerprint := hexToByte("0102030405060708090A0B0C0D0E0F1011121314")
	bobFingerprint := hexToByte("3132333435363738393A3B3C3D3E3F4041424344")
	ssid := hexToByte("FFF1D1E412345668")
	secret := []byte("this is something secret")
	result := generateSMPSecret(aliceFingerprint, bobFingerprint, ssid, secret)
	assertDeepEquals(t, result, hexToByte("D9B2E56321F9A9F8E364607C8C82DECD8E8E6209E2CB952C7E649620F5286FE3"))
}