package otr3

import (
	"errors"
	"math/big"
	"testing"
)

func Test_generateSMPSecretGeneratesASecret(t *testing.T) {
	aliceFingerprint := hexToByte("0102030405060708090A0B0C0D0E0F1011121314")
	bobFingerprint := hexToByte("3132333435363738393A3B3C3D3E3F4041424344")
	ssid := hexToByte("FFF1D1E412345668")
	secret := []byte("this is something secret")
	result := generateSMPSecret(aliceFingerprint, bobFingerprint, ssid, secret)
	assertDeepEquals(t, result, hexToByte("D9B2E56321F9A9F8E364607C8C82DECD8E8E6209E2CB952C7E649620F5286FE3"))
}

func Test_generatesLongerAandRValuesForOtrV3(t *testing.T) {
	otr := context{otrV3{}, fixtureRand()}
	smp := otr.generateSMPStartParameters()
	assertDeepEquals(t, smp.a2, fixtureLong1)
	assertDeepEquals(t, smp.a3, fixtureLong2)
	assertDeepEquals(t, smp.r2, fixtureLong3)
	assertDeepEquals(t, smp.r3, fixtureLong4)
}

func Test_generatesShorterAandRValuesForOtrV2(t *testing.T) {
	otr := context{otrV2{}, fixtureRand()}
	smp := otr.generateSMPStartParameters()
	assertDeepEquals(t, smp.a2, fixtureShort1)
	assertDeepEquals(t, smp.a3, fixtureShort2)
	assertDeepEquals(t, smp.r2, fixtureShort3)
	assertDeepEquals(t, smp.r3, fixtureShort4)
}

func Test_computesG2aAndG3aCorrectlyForOtrV3(t *testing.T) {
	otr := context{otrV3{}, fixtureRand()}
	smp := otr.generateSMPStartParameters()
	assertDeepEquals(t, smp.msg.g2a, fixtureMessage1_v3().g2a)
	assertDeepEquals(t, smp.msg.g3a, fixtureMessage1_v3().g3a)
}

func Test_computesG2aAndG3aCorrectlyForOtrV2(t *testing.T) {
	otr := context{otrV2{}, fixtureRand()}
	smp := otr.generateSMPStartParameters()
	assertDeepEquals(t, smp.msg.g2a, fixtureMessage1().g2a)
	assertDeepEquals(t, smp.msg.g3a, fixtureMessage1().g3a)
}

func Test_computesC2AndD2CorrectlyForOtrV2(t *testing.T) {
	otr := context{otrV2{}, fixtureRand()}
	smp := otr.generateSMPStartParameters()
	assertDeepEquals(t, smp.msg.c2, fixtureMessage1().c2)
	assertDeepEquals(t, smp.msg.d2, fixtureMessage1().d2)
}

func Test_computesC3AndD3CorrectlyForOtrV2(t *testing.T) {
	otr := context{otrV2{}, fixtureRand()}
	smp := otr.generateSMPStartParameters()
	assertDeepEquals(t, smp.msg.c3, fixtureMessage1().c3)
	assertDeepEquals(t, smp.msg.d3, fixtureMessage1().d3)
}

func Test_thatVerifySMPStartParametersCheckG2AForOtrV3(t *testing.T) {
	otr := context{otrV3{}, fixtureRand()}
	err := otr.verifySMPStartParameters(smpMessage1{g2a: new(big.Int).SetInt64(1)})
	assertDeepEquals(t, err, errors.New("g2a is an invalid group element"))
}

func Test_thatVerifySMPStartParametersCheckG3AForOtrV3(t *testing.T) {
	otr := context{otrV3{}, fixtureRand()}
	err := otr.verifySMPStartParameters(smpMessage1{g2a: new(big.Int).SetInt64(3), g3a: p})
	assertDeepEquals(t, err, errors.New("g3a is an invalid group element"))
}

func Test_thatVerifySMPStartParametersDoesntCheckG2AForOtrV2(t *testing.T) {
	otr := context{otrV2{}, fixtureRand()}
	err := otr.verifySMPStartParameters(smpMessage1{
		g2a: new(big.Int).SetInt64(1),
		g3a: new(big.Int).SetInt64(1),
		c2:  new(big.Int).SetInt64(1),
		c3:  new(big.Int).SetInt64(1),
		d2:  new(big.Int).SetInt64(1),
		d3:  new(big.Int).SetInt64(1),
	})
	assertDeepEquals(t, err, errors.New("c2 is not a valid zero knowledge proof"))
}

func Test_thatVerifySMPStartParametersDoesntCheckG3AForOtrV2(t *testing.T) {
	otr := context{otrV2{}, fixtureRand()}
	err := otr.verifySMPStartParameters(smpMessage1{
		g2a: new(big.Int).SetInt64(3),
		g3a: new(big.Int).SetInt64(1),
		c2:  new(big.Int).SetInt64(1),
		c3:  new(big.Int).SetInt64(1),
		d2:  new(big.Int).SetInt64(1),
		d3:  new(big.Int).SetInt64(1),
	})
	assertDeepEquals(t, err, errors.New("c2 is not a valid zero knowledge proof"))
}

func Test_thatVerifySMPStartParametersChecksThatc2IsAValidZeroKnowledgeProof(t *testing.T) {
	otr := context{otrV3{}, fixtureRand()}
	err := otr.verifySMPStartParameters(smpMessage1{
		g2a: new(big.Int).SetInt64(3),
		g3a: new(big.Int).SetInt64(3),
		c2:  new(big.Int).SetInt64(3),
		c3:  new(big.Int).SetInt64(3),
		d2:  new(big.Int).SetInt64(3),
		d3:  new(big.Int).SetInt64(3),
	})
	assertDeepEquals(t, err, errors.New("c2 is not a valid zero knowledge proof"))
}

func Test_thatVerifySMPStartParametersChecksThatc3IsAValidZeroKnowledgeProof(t *testing.T) {
	otr := context{otrV3{}, fixtureRand()}

	err := otr.verifySMPStartParameters(smpMessage1{
		g2a: fixtureMessage1().g2a,
		g3a: new(big.Int).SetInt64(3),
		c2:  fixtureMessage1().c2,
		c3:  new(big.Int).SetInt64(3),
		d2:  fixtureMessage1().d2,
		d3:  new(big.Int).SetInt64(3),
	})
	assertDeepEquals(t, err, errors.New("c3 is not a valid zero knowledge proof"))
}

func Test_thatVerifySMPStartParametersIsOKWithAValidParameterMessage(t *testing.T) {
	otr := context{otrV3{}, fixtureRand()}

	g2a, _ := new(big.Int).SetString("8a88c345c63aa25dab9815f8c51f6b7b621a12d31c8220a0579381c1e2e85a2275e2407c79c8e6e1f72ae765804e6b4562ac1b2d634313c70d59752ac119c6da5cb95dde3eedd9c48595b37256f5b64c56fb938eb1131447c9af9054b42841c57d1f41fe5aa510e2bd2965434f46dd0473c60d6114da088c7047760b00bc10287a03afc4c4f30e1c7dd7c9dbd51bdbd049eb2b8921cbdc72b4f69309f61e559c2d6dec9c9ce6f38ccb4dfd07f4cf2cf6e76279b88b297848c473e13f091a0f77", 16)
	g3a, _ := new(big.Int).SetString("d275468351fd48246e406ee74a8dc3db6ee335067bfa63300ce6a23867a1b2beddbdae9a8a36555fd4837f3ef8bad4f7fd5d7b4f346d7c7b7cb64bd7707eeb515902c66aa0c9323931364471ab93dd315f65c6624c956d74680863a9388cd5d89f1b5033b1cf232b8b6dcffaaea195de4e17cc1ba4c99497be18c011b2ad7742b43fa9ee3f95f7b6da02c8e894d054eb178a7822273655dc286ad15874687fe6671908d83662e7a529744ce4ea8dad49290d19dbe6caba202a825a20a27ee98a", 16)
	c2, _ := new(big.Int).SetString("d3b6ef5528fa97e983395bec165fa4ced7657bdabf3742d60880965c369c880c", 16)
	d2, _ := new(big.Int).SetString("7fffffffffffffffe487ed5110b4611a62633145c06e0e68948127044533e63a0105df531d89cd9128a5043cc71a026ef7ca8cd9e69d218d98158536f92f8a1ba7f09ab6b6a8e122f242dabb312f3f637a262174d31bf6b585ffae5b7a035bf6f71c35fdad44cfd2d74f9208be258ff324943328f6722d9ee1003e5c50b1df82cc6d241b0e2ae9cd348b1fd47e9267af339d65211b4fcfa466656c89b4217f90102e4aa3ac176a41f6240f32689712b0391c1c659757f4bfb83e6ba66bf8b630", 16)
	c3, _ := new(big.Int).SetString("57d8cfda442854ecb01b28e631aa9165d51d1192f7f464bf17ea7f6665c05030", 16)
	d3, _ := new(big.Int).SetString("7fffffffffffffffe487ed5110b4611a62633145c06e0e68948127044533e63a0105df531d89cd9128a5043cc71a026ef7ca8cd9e69d218d98158536f92f8a1ba7f09ab6b6a8e122f242dabb312f3f637a262174d31bf6b585ffae5b7a035bf6f71c35fdad44cfd2d74f9208be258ff324943328f6722d9ee1003e5c50b1df82cc6d241b0e2ae9cd348b1fd47e9267af8140bb2aa65628bcff455920bba95a1392f2fcb5c115f43a7a828b5bf0393c5c775a17a88506a7893ff509d674cd655c", 16)

	err := otr.verifySMPStartParameters(smpMessage1{
		g2a: g2a,
		g3a: g3a,
		c2:  c2,
		c3:  c3,
		d2:  d2,
		d3:  d3,
	})
	assertDeepEquals(t, err, nil)
}

func Test_thatVerifySMPStartParametersIsOKWithAValidParameterMessageWithProtocolV2(t *testing.T) {
	otr := context{otrV2{}, fixtureRand()}

	g2a, _ := new(big.Int).SetString("8a88c345c63aa25dab9815f8c51f6b7b621a12d31c8220a0579381c1e2e85a2275e2407c79c8e6e1f72ae765804e6b4562ac1b2d634313c70d59752ac119c6da5cb95dde3eedd9c48595b37256f5b64c56fb938eb1131447c9af9054b42841c57d1f41fe5aa510e2bd2965434f46dd0473c60d6114da088c7047760b00bc10287a03afc4c4f30e1c7dd7c9dbd51bdbd049eb2b8921cbdc72b4f69309f61e559c2d6dec9c9ce6f38ccb4dfd07f4cf2cf6e76279b88b297848c473e13f091a0f77", 16)
	g3a, _ := new(big.Int).SetString("d275468351fd48246e406ee74a8dc3db6ee335067bfa63300ce6a23867a1b2beddbdae9a8a36555fd4837f3ef8bad4f7fd5d7b4f346d7c7b7cb64bd7707eeb515902c66aa0c9323931364471ab93dd315f65c6624c956d74680863a9388cd5d89f1b5033b1cf232b8b6dcffaaea195de4e17cc1ba4c99497be18c011b2ad7742b43fa9ee3f95f7b6da02c8e894d054eb178a7822273655dc286ad15874687fe6671908d83662e7a529744ce4ea8dad49290d19dbe6caba202a825a20a27ee98a", 16)
	c2, _ := new(big.Int).SetString("d3b6ef5528fa97e983395bec165fa4ced7657bdabf3742d60880965c369c880c", 16)
	d2, _ := new(big.Int).SetString("7fffffffffffffffe487ed5110b4611a62633145c06e0e68948127044533e63a0105df531d89cd9128a5043cc71a026ef7ca8cd9e69d218d98158536f92f8a1ba7f09ab6b6a8e122f242dabb312f3f637a262174d31bf6b585ffae5b7a035bf6f71c35fdad44cfd2d74f9208be258ff324943328f6722d9ee1003e5c50b1df82cc6d241b0e2ae9cd348b1fd47e9267af339d65211b4fcfa466656c89b4217f90102e4aa3ac176a41f6240f32689712b0391c1c659757f4bfb83e6ba66bf8b630", 16)
	c3, _ := new(big.Int).SetString("57d8cfda442854ecb01b28e631aa9165d51d1192f7f464bf17ea7f6665c05030", 16)
	d3, _ := new(big.Int).SetString("7fffffffffffffffe487ed5110b4611a62633145c06e0e68948127044533e63a0105df531d89cd9128a5043cc71a026ef7ca8cd9e69d218d98158536f92f8a1ba7f09ab6b6a8e122f242dabb312f3f637a262174d31bf6b585ffae5b7a035bf6f71c35fdad44cfd2d74f9208be258ff324943328f6722d9ee1003e5c50b1df82cc6d241b0e2ae9cd348b1fd47e9267af8140bb2aa65628bcff455920bba95a1392f2fcb5c115f43a7a828b5bf0393c5c775a17a88506a7893ff509d674cd655c", 16)

	err := otr.verifySMPStartParameters(smpMessage1{
		g2a: g2a,
		g3a: g3a,
		c2:  c2,
		c3:  c3,
		d2:  d2,
		d3:  d3,
	})
	assertDeepEquals(t, err, nil)
}

func Test_generateSMPSecondParameters_generatesLongerValuesForBAndRWithProtocolV3(t *testing.T) {
	otr := context{otrV3{}, fixtureRand()}
	smp1 := fixtureMessage1()
	smp := otr.generateSMPSecondParameters(fixtureSecret(), smp1)
	assertDeepEquals(t, smp.b2, fixtureLong1)
	assertDeepEquals(t, smp.b3, fixtureLong2)
	assertDeepEquals(t, smp.r2, fixtureLong3)
	assertDeepEquals(t, smp.r3, fixtureLong4)
	assertDeepEquals(t, smp.r4, fixtureLong5)
	assertDeepEquals(t, smp.r5, fixtureLong6)
	assertDeepEquals(t, smp.r6, fixtureLong7)
}

func Test_generateSMPSecondParameters_generatesShorterValuesForBAndRWithProtocolV2(t *testing.T) {
	otr := context{otrV2{}, fixtureRand()}
	smp1 := fixtureMessage1()
	smp := otr.generateSMPSecondParameters(fixtureSecret(), smp1)
	assertDeepEquals(t, smp.b2, fixtureShort1)
	assertDeepEquals(t, smp.b3, fixtureShort2)
	assertDeepEquals(t, smp.r2, fixtureShort3)
	assertDeepEquals(t, smp.r3, fixtureShort4)
	assertDeepEquals(t, smp.r4, fixtureShort5)
	assertDeepEquals(t, smp.r5, fixtureShort6)
	assertDeepEquals(t, smp.r6, fixtureShort7)
}

func Test_generateSMPSecondParameters_computesG2bAndG3bCorrectlyForOtrV2(t *testing.T) {
	otr := context{otrV2{}, fixtureRand()}
	smp1 := fixtureMessage1()
	smp := otr.generateSMPSecondParameters(fixtureSecret(), smp1)
	assertDeepEquals(t, smp.msg.g2b, fixtureMessage2().g2b)
	assertDeepEquals(t, smp.msg.g3b, fixtureMessage2().g3b)
}

func Test_generateSMPSecondParameters_computesC2AndD2CorrectlyForOtrV2(t *testing.T) {
	otr := context{otrV2{}, fixtureRand()}
	smp1 := fixtureMessage1()
	smp := otr.generateSMPSecondParameters(fixtureSecret(), smp1)
	assertDeepEquals(t, smp.msg.c2, fixtureMessage2().c2)
	assertDeepEquals(t, smp.msg.d2, fixtureMessage2().d2)
}

func Test_generateSMPSecondParameters_computesC3AndD3CorrectlyForOtrV2(t *testing.T) {
	otr := context{otrV2{}, fixtureRand()}
	smp1 := fixtureMessage1()
	smp := otr.generateSMPSecondParameters(fixtureSecret(), smp1)
	assertDeepEquals(t, smp.msg.c3, fixtureMessage2().c3)
	assertDeepEquals(t, smp.msg.d3, fixtureMessage2().d3)
}

func Test_generateSMPSecondParameters_computesG2AndG3Correctly(t *testing.T) {
	otr := context{otrV2{}, fixtureRand()}
	smp1 := fixtureMessage1()
	smp := otr.generateSMPSecondParameters(fixtureSecret(), smp1)
	assertDeepEquals(t, smp.msg.g2, fixtureMessage2().g2)
	assertDeepEquals(t, smp.msg.g3, fixtureMessage2().g3)
}

func Test_generateSMPSecondParameters_computesPbAndQbCorrectly(t *testing.T) {
	otr := context{otrV2{}, fixtureRand()}
	smp1 := fixtureMessage1()
	smp := otr.generateSMPSecondParameters(fixtureSecret(), smp1)
	assertDeepEquals(t, smp.msg.pb, fixtureMessage2().pb)
	assertDeepEquals(t, smp.msg.qb, fixtureMessage2().qb)
}

func Test_generateSMPSecondParameters_computesCPCorrectly(t *testing.T) {
	otr := context{otrV2{}, fixtureRand()}
	smp1 := fixtureMessage1()
	smp := otr.generateSMPSecondParameters(fixtureSecret(), smp1)
	assertDeepEquals(t, smp.msg.cp, fixtureMessage2().cp)
}

func Test_generateSMPSecondParameters_computesD5Correctly(t *testing.T) {
	otr := context{otrV2{}, fixtureRand()}
	smp1 := fixtureMessage1()
	smp := otr.generateSMPSecondParameters(fixtureSecret(), smp1)
	assertDeepEquals(t, smp.msg.d5, fixtureMessage2().d5)
}

func Test_generateSMPSecondParameters_computesD6Correctly(t *testing.T) {
	otr := context{otrV2{}, fixtureRand()}
	smp1 := fixtureMessage1()
	smp := otr.generateSMPSecondParameters(fixtureSecret(), smp1)
	assertDeepEquals(t, smp.msg.d6, fixtureMessage2().d6)
}

func Test_verifySMPSecondParameters_checkG2bForOtrV3(t *testing.T) {
	otr := context{otrV3{}, fixtureRand()}
	err := otr.verifySMPSecondParameters(smpMessage2{g2b: new(big.Int).SetInt64(1)})
	assertDeepEquals(t, err, errors.New("g2b is an invalid group element"))
}

func Test_verifySMPSecondParameters_checkG3bForOtrV3(t *testing.T) {
	otr := context{otrV3{}, fixtureRand()}
	err := otr.verifySMPSecondParameters(smpMessage2{
		g2b: new(big.Int).SetInt64(3),
		g3b: new(big.Int).SetInt64(1),
	})
	assertDeepEquals(t, err, errors.New("g3b is an invalid group element"))
}

func Test_verifySMPSecondParameters_checkPbForOtrV3(t *testing.T) {
	otr := context{otrV3{}, fixtureRand()}
	err := otr.verifySMPSecondParameters(smpMessage2{
		g2b: new(big.Int).SetInt64(3),
		g3b: new(big.Int).SetInt64(3),
		pb:  p,
	})
	assertDeepEquals(t, err, errors.New("Pb is an invalid group element"))
}

func Test_verifySMPSecondParameters_checkQbForOtrV3(t *testing.T) {
	otr := context{otrV3{}, fixtureRand()}
	err := otr.verifySMPSecondParameters(smpMessage2{
		g2b: new(big.Int).SetInt64(3),
		g3b: new(big.Int).SetInt64(3),
		pb:  pMinusTwo,
		qb:  new(big.Int).SetInt64(1),
	})
	assertDeepEquals(t, err, errors.New("Qb is an invalid group element"))
}

func Test_verifySMPSecondParameters_failsIfC2IsNotACorrectZKP(t *testing.T) {
	otr := context{otrV3{}, fixtureRand()}
	s2 := fixtureMessage2()
	s2.c2 = sub(s2.c2, big.NewInt(1))
	err := otr.verifySMPSecondParameters(s2)
	assertDeepEquals(t, err, errors.New("c2 is not a valid zero knowledge proof"))
}

func Test_verifySMPSecondParameters_failsIfC3IsNotACorrectZKP(t *testing.T) {
	otr := context{otrV3{}, fixtureRand()}
	s2 := fixtureMessage2()
	s2.c3 = sub(s2.c3, big.NewInt(1))
	err := otr.verifySMPSecondParameters(s2)
	assertDeepEquals(t, err, errors.New("c3 is not a valid zero knowledge proof"))
}

func Test_verifySMPSecondParameters_failsIfCpIsNotACorrectZKP(t *testing.T) {
	otr := context{otrV3{}, fixtureRand()}
	s2 := fixtureMessage2()
	s2.cp = sub(s2.cp, big.NewInt(1))
	err := otr.verifySMPSecondParameters(s2)
	assertDeepEquals(t, err, errors.New("cP is not a valid zero knowledge proof"))
}

func Test_verifySMPSecondParameters_succeedsForACorrectZKP(t *testing.T) {
	otr := context{otrV3{}, fixtureRand()}
	err := otr.verifySMPSecondParameters(fixtureMessage2())
	assertDeepEquals(t, err, nil)
}

func Test_generateSMPThirdParameters_generatesLongerValuesForR4WithProtocolV3(t *testing.T) {
	otr := context{otrV3{}, fixtureRand()}
	smp := otr.generateSMPThirdParameters(fixtureSecret(), fixtureSmp1(), fixtureMessage2())
	assertDeepEquals(t, smp.r4, fixtureLong1)
}

func Test_generateSMPThirdParameters_generatesLongerValuesForR5WithProtocolV3(t *testing.T) {
	otr := context{otrV3{}, fixtureRand()}
	smp := otr.generateSMPThirdParameters(fixtureSecret(), fixtureSmp1(), fixtureMessage2())
	assertDeepEquals(t, smp.r5, fixtureLong2)
}

func Test_generateSMPThirdParameters_generatesLongerValuesForR6WithProtocolV3(t *testing.T) {
	otr := context{otrV3{}, fixtureRand()}
	smp := otr.generateSMPThirdParameters(fixtureSecret(), fixtureSmp1(), fixtureMessage2())
	assertDeepEquals(t, smp.r6, fixtureLong3)
}

func Test_generateSMPThirdParameters_generatesLongerValuesForR7WithProtocolV3(t *testing.T) {
	otr := context{otrV3{}, fixtureRand()}
	smp := otr.generateSMPThirdParameters(fixtureSecret(), fixtureSmp1(), fixtureMessage2())
	assertDeepEquals(t, smp.r7, fixtureLong4)
}

func Test_generateSMPThirdParameters_generatesShorterValuesForR4WithProtocolV2(t *testing.T) {
	otr := context{otrV2{}, fixtureRand()}
	smp := otr.generateSMPThirdParameters(fixtureSecret(), fixtureSmp1(), fixtureMessage2())
	assertDeepEquals(t, smp.r4, fixtureShort1)
}

func Test_generateSMPThirdParameters_computesG2Correctly(t *testing.T) {
	otr := context{otrV2{}, fixtureRand()}
	smp := otr.generateSMPThirdParameters(fixtureSecret(), fixtureSmp1(), fixtureMessage2())
	assertDeepEquals(t, smp.msg.g2, fixtureMessage3().g2)
}

func Test_generateSMPThirdParameters_computesG3Correctly(t *testing.T) {
	otr := context{otrV2{}, fixtureRand()}
	smp := otr.generateSMPThirdParameters(fixtureSecret(), fixtureSmp1(), fixtureMessage2())
	assertDeepEquals(t, smp.msg.g3, fixtureMessage3().g3)
}

func Test_generateSMPThirdParameters_computesPaCorrectly(t *testing.T) {
	otr := context{otrV2{}, fixtureRand()}
	smp := otr.generateSMPThirdParameters(fixtureSecret(), fixtureSmp1(), fixtureMessage2())
	assertDeepEquals(t, smp.msg.pa, fixtureMessage3().pa)
}

func Test_generateSMPThirdParameters_computesQaCorrectly(t *testing.T) {
	otr := context{otrV2{}, fixtureRand()}
	smp := otr.generateSMPThirdParameters(fixtureSecret(), fixtureSmp1(), fixtureMessage2())
	assertDeepEquals(t, smp.msg.qa, fixtureMessage3().qa)
}

func Test_generateSMPThirdParameters_computesCPCorrectly(t *testing.T) {
	otr := context{otrV2{}, fixtureRand()}
	smp := otr.generateSMPThirdParameters(fixtureSecret(), fixtureSmp1(), fixtureMessage2())
	assertDeepEquals(t, smp.msg.cp, fixtureMessage3().cp)
}

func Test_generateSMPThirdParameters_computesD5Correctly(t *testing.T) {
	otr := context{otrV2{}, fixtureRand()}
	smp := otr.generateSMPThirdParameters(fixtureSecret(), fixtureSmp1(), fixtureMessage2())
	assertDeepEquals(t, smp.msg.d5, fixtureMessage3().d5)
}

func Test_generateSMPThirdParameters_computesD6Correctly(t *testing.T) {
	otr := context{otrV2{}, fixtureRand()}
	smp := otr.generateSMPThirdParameters(fixtureSecret(), fixtureSmp1(), fixtureMessage2())
	assertDeepEquals(t, smp.msg.d6, fixtureMessage3().d6)
}

func Test_generateSMPThirdParameters_computesRaCorrectly(t *testing.T) {
	otr := context{otrV2{}, fixtureRand()}
	smp := otr.generateSMPThirdParameters(fixtureSecret(), fixtureSmp1(), fixtureMessage2())
	assertDeepEquals(t, smp.msg.ra, fixtureMessage3().ra)
}

func Test_generateSMPThirdParameters_computesCrCorrectly(t *testing.T) {
	otr := context{otrV2{}, fixtureRand()}
	smp := otr.generateSMPThirdParameters(fixtureSecret(), fixtureSmp1(), fixtureMessage2())
	assertDeepEquals(t, smp.msg.cr, fixtureMessage3().cr)
}

func Test_generateSMPThirdParameters_computesD7Correctly(t *testing.T) {
	otr := context{otrV2{}, fixtureRand()}
	smp := otr.generateSMPThirdParameters(fixtureSecret(), fixtureSmp1(), fixtureMessage2())
	assertDeepEquals(t, smp.msg.d7, fixtureMessage3().d7)
}

func Test_verifySMP3Parameters_failsIfPaIsNotInTheGroupForProtocolV3(t *testing.T) {
	otr := context{otrV3{}, fixtureRand()}
	err := otr.verifySMP3Parameters(smpMessage3{pa: big.NewInt(1)})
	assertDeepEquals(t, err, errors.New("Pa is an invalid group element"))
}

func Test_verifySMP3Parameters_failsIfQaIsNotInTheGroupForProtocolV3(t *testing.T) {
	otr := context{otrV3{}, fixtureRand()}
	err := otr.verifySMP3Parameters(smpMessage3{
		pa: big.NewInt(2),
		qa: big.NewInt(1),
	})
	assertDeepEquals(t, err, errors.New("Qa is an invalid group element"))
}

func Test_verifySMP3Parameters_failsIfRaIsNotInTheGroupForProtocolV3(t *testing.T) {
	otr := context{otrV3{}, fixtureRand()}
	err := otr.verifySMP3Parameters(smpMessage3{
		pa: big.NewInt(2),
		qa: big.NewInt(2),
		ra: big.NewInt(1),
	})
	assertDeepEquals(t, err, errors.New("Ra is an invalid group element"))
}

func Test_verifySMP3Parameters_succeedsForValidZKPS(t *testing.T) {
	otr := context{otrV2{}, fixtureRand()}
	err := otr.verifySMP3Parameters(fixtureMessage3())
	assertDeepEquals(t, err, nil)
}

func Test_verifySMP3Parameters_failsIfCpIsNotAValidZKP(t *testing.T) {
	otr := context{otrV2{}, fixtureRand()}
	m := fixtureMessage3()
	m.cp = sub(m.cp, big.NewInt(1))
	err := otr.verifySMP3Parameters(m)
	assertDeepEquals(t, err, errors.New("cP is not a valid zero knowledge proof"))
}
