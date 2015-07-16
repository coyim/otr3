package otr3

import (
	"crypto/rand"
	"testing"
)

func TestFullSMPHandshake(t *testing.T) {
	secret := bnFromHex("ABCDE56321F9A9F8E364607C8C82DECD8E8E6209E2CB952C7E649620F5286FE3")
	alice := newConversation(otrV3{}, rand.Reader)
	bob := newConversation(otrV3{}, rand.Reader)

	// Alice -> Bob
	// Stores: x, a2, and a3
	// Sends: g2a, c2, D2, g3a, c3 and D3
	s1 := alice.generateSMPStartParameters()

	//Bob
	err := bob.verifySMPStartParameters(s1.msg)
	assertDeepEquals(t, err, nil)

	// Bob -> Alice
	// Stores: g3a, g2, g3, b3, Pb and Qb
	// Sends: g2b, c2, D2, g3b, c3, D3, Pb, Qb, cP, D5 and D6
	s2 := bob.generateSMPSecondParameters(secret, s1.msg)

	// Alice
	err = alice.verifySMPSecondParameters(s1, s2.msg)
	assertDeepEquals(t, err, nil)

	// Alice -> Bob
	// Stores: g3b, (Pa / Pb), (Qa / Qb) and Ra
	// Sends: Pa, Qa, cP, D5, D6, Ra, cR and D7
	s3 := alice.generateSMPThirdParameters(secret, s1, s2.msg)

	// Bob
	err = bob.verifySMP3Parameters(s2, s3.msg)
	assertDeepEquals(t, err, nil)

	err = bob.verifySMP3ProtocolSuccess(s2, s3.msg)
	assertDeepEquals(t, err, nil)

	// Bob -> Alice
	// Stores: ???
	// Sends: Rb, cR and D7
	s4 := bob.generateSMPFourthParameters(secret, s2, s3.msg)

	// Alice
	err = alice.verifySMP4Parameters(s3, s4.msg)
	assertDeepEquals(t, err, nil)

	err = alice.verifySMP4ProtocolSuccess(s1, s3, s4.msg)
	assertDeepEquals(t, err, nil)
}
