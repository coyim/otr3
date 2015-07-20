package otr3

import (
	"errors"
	"math/big"
	"testing"
)

func Test_generateSMPSecondParameters_generatesLongerValuesForBAndRWithProtocolV3(t *testing.T) {
	otr := newOtrContext(otrV3{}, fixtureRand())
	smp1 := fixtureMessage1()
	smp, ok := otr.generateSMPSecondParameters(fixtureSecret(), smp1)
	assertDeepEquals(t, smp.b2, fixtureLong1)
	assertDeepEquals(t, smp.b3, fixtureLong2)
	assertDeepEquals(t, smp.r2, fixtureLong3)
	assertDeepEquals(t, smp.r3, fixtureLong4)
	assertDeepEquals(t, smp.r4, fixtureLong5)
	assertDeepEquals(t, smp.r5, fixtureLong6)
	assertDeepEquals(t, smp.r6, fixtureLong7)
	assertDeepEquals(t, ok, true)
}

func Test_generateSMPSecondParameters_willReturnNotOKIfThereIsntEnoughRandomnessForBlindingParameters(t *testing.T) {
	otr := newOtrContext(otrV2{}, fixedRand([]string{
		"1a2a3a4a5a6a7a8a1b2b3b4b5b6b7b8b",
		"1a2a3a4a5a6a7a8a1b2b3b4b5b6b7b",
	}))
	_, ok := otr.generateSMPSecondParameters(fixtureSecret(), fixtureMessage1())
	assertDeepEquals(t, ok, false)
}

func Test_generateSecondaryParameters_willReturnNotOKIfThereIsNotEnoughRandomnessForEachOfTheBlindingParameters_for_b2(t *testing.T) {
	_, ok := newOtrContext(otrV2{}, fixedRand([]string{"1a2a3a4a5a6a7a8a1b2b3b4b5b6b7b"})).generateSecondaryParameters()
	assertDeepEquals(t, ok, false)
}

func Test_generateSecondaryParameters_willReturnNotOKIfThereIsNotEnoughRandomnessForEachOfTheBlindingParameters_for_b3(t *testing.T) {
	_, ok := newOtrContext(otrV2{}, fixedRand([]string{
		"1a2a3a4a5a6a7a8a1b2b3b4b5b6b7b8b",
		"1a2a3a4a5a6a7a8a1b2b3b4b5b6b7b",
	})).generateSecondaryParameters()
	assertDeepEquals(t, ok, false)
}

func Test_generateSecondaryParameters_willReturnNotOKIfThereIsNotEnoughRandomnessForEachOfTheBlindingParameters_for_r2(t *testing.T) {
	_, ok := newOtrContext(otrV2{}, fixedRand([]string{
		"1a2a3a4a5a6a7a8a1b2b3b4b5b6b7b8b",
		"1a2a3a4a5a6a7a8a1b2b3b4b5b6b7b8b",
		"1a2a3a4a5a6a7a8a1b2b3b4b5b6b7b",
	})).generateSecondaryParameters()
	assertDeepEquals(t, ok, false)
}

func Test_generateSecondaryParameters_willReturnNotOKIfThereIsNotEnoughRandomnessForEachOfTheBlindingParameters_for_r3(t *testing.T) {
	_, ok := newOtrContext(otrV2{}, fixedRand([]string{
		"1a2a3a4a5a6a7a8a1b2b3b4b5b6b7b8b",
		"1a2a3a4a5a6a7a8a1b2b3b4b5b6b7b8b",
		"1a2a3a4a5a6a7a8a1b2b3b4b5b6b7b8b",
		"1a2a3a4a5a6a7a8a1b2b3b4b5b6b7b",
	})).generateSecondaryParameters()
	assertDeepEquals(t, ok, false)
}

func Test_generateSecondaryParameters_willReturnNotOKIfThereIsNotEnoughRandomnessForEachOfTheBlindingParameters_for_r4(t *testing.T) {
	_, ok := newOtrContext(otrV2{}, fixedRand([]string{
		"1a2a3a4a5a6a7a8a1b2b3b4b5b6b7b8b",
		"1a2a3a4a5a6a7a8a1b2b3b4b5b6b7b8b",
		"1a2a3a4a5a6a7a8a1b2b3b4b5b6b7b8b",
		"1a2a3a4a5a6a7a8a1b2b3b4b5b6b7b8b",
		"1a2a3a4a5a6a7a8a1b2b3b4b5b6b7b",
	})).generateSecondaryParameters()
	assertDeepEquals(t, ok, false)
}

func Test_generateSecondaryParameters_willReturnNotOKIfThereIsNotEnoughRandomnessForEachOfTheBlindingParameters_for_r5(t *testing.T) {
	_, ok := newOtrContext(otrV2{}, fixedRand([]string{
		"1a2a3a4a5a6a7a8a1b2b3b4b5b6b7b8b",
		"1a2a3a4a5a6a7a8a1b2b3b4b5b6b7b8b",
		"1a2a3a4a5a6a7a8a1b2b3b4b5b6b7b8b",
		"1a2a3a4a5a6a7a8a1b2b3b4b5b6b7b8b",
		"1a2a3a4a5a6a7a8a1b2b3b4b5b6b7b8b",
		"1a2a3a4a5a6a7a8a1b2b3b4b5b6b7b",
	})).generateSecondaryParameters()
	assertDeepEquals(t, ok, false)
}

func Test_generateSecondaryParameters_willReturnNotOKIfThereIsNotEnoughRandomnessForEachOfTheBlindingParameters_for_r6(t *testing.T) {
	_, ok := newOtrContext(otrV2{}, fixedRand([]string{
		"1a2a3a4a5a6a7a8a1b2b3b4b5b6b7b8b",
		"1a2a3a4a5a6a7a8a1b2b3b4b5b6b7b8b",
		"1a2a3a4a5a6a7a8a1b2b3b4b5b6b7b8b",
		"1a2a3a4a5a6a7a8a1b2b3b4b5b6b7b8b",
		"1a2a3a4a5a6a7a8a1b2b3b4b5b6b7b8b",
		"1a2a3a4a5a6a7a8a1b2b3b4b5b6b7b8b",
		"1a2a3a4a5a6a7a8a1b2b3b4b5b6b7b",
	})).generateSecondaryParameters()
	assertDeepEquals(t, ok, false)
}

func Test_generateSecondaryParameters_willReturnOKIfThereIsEnoughRandomnessForAllParameters(t *testing.T) {
	_, ok := newOtrContext(otrV2{}, fixedRand([]string{
		"1a2a3a4a5a6a7a8a1b2b3b4b5b6b7b8b",
		"1a2a3a4a5a6a7a8a1b2b3b4b5b6b7b8b",
		"1a2a3a4a5a6a7a8a1b2b3b4b5b6b7b8b",
		"1a2a3a4a5a6a7a8a1b2b3b4b5b6b7b8b",
		"1a2a3a4a5a6a7a8a1b2b3b4b5b6b7b8b",
		"1a2a3a4a5a6a7a8a1b2b3b4b5b6b7b8b",
		"1a2a3a4a5a6a7a8a1b2b3b4b5b6b7b8b",
	})).generateSecondaryParameters()
	assertDeepEquals(t, ok, true)
}

func Test_generateSMPSecondParameters_generatesShorterValuesForBAndRWithProtocolV2(t *testing.T) {
	otr := newOtrContext(otrV2{}, fixtureRand())
	smp1 := fixtureMessage1()
	smp, _ := otr.generateSMPSecondParameters(fixtureSecret(), smp1)
	assertDeepEquals(t, smp.b2, fixtureShort1)
	assertDeepEquals(t, smp.b3, fixtureShort2)
	assertDeepEquals(t, smp.r2, fixtureShort3)
	assertDeepEquals(t, smp.r3, fixtureShort4)
	assertDeepEquals(t, smp.r4, fixtureShort5)
	assertDeepEquals(t, smp.r5, fixtureShort6)
	assertDeepEquals(t, smp.r6, fixtureShort7)
}

func Test_generateSMPSecondParameters_computesG2AndG3CorrectlyForOtrV2(t *testing.T) {
	otr := newOtrContext(otrV2{}, fixtureRand())
	smp1 := fixtureMessage1()
	smp, _ := otr.generateSMPSecondParameters(fixtureSecret(), smp1)
	assertDeepEquals(t, smp.g2, fixtureSmp2().g2)
	assertDeepEquals(t, smp.g3, fixtureSmp2().g3)
}

func Test_generateSMPSecondParameters_storesG3ForOtrV2(t *testing.T) {
	otr := newOtrContext(otrV2{}, fixtureRand())
	smp1 := fixtureMessage1()
	smp, _ := otr.generateSMPSecondParameters(fixtureSecret(), smp1)
	assertDeepEquals(t, smp.g3a, smp1.g3a)
}

func Test_generateSMPSecondParameters_computesG2bAndG3bCorrectlyForOtrV2(t *testing.T) {
	otr := newOtrContext(otrV2{}, fixtureRand())
	smp1 := fixtureMessage1()
	smp, _ := otr.generateSMPSecondParameters(fixtureSecret(), smp1)
	assertDeepEquals(t, smp.msg.g2b, fixtureMessage2().g2b)
	assertDeepEquals(t, smp.msg.g3b, fixtureMessage2().g3b)
}

func Test_generateSMPSecondParameters_computesC2AndD2CorrectlyForOtrV2(t *testing.T) {
	otr := newOtrContext(otrV2{}, fixtureRand())
	smp1 := fixtureMessage1()
	smp, _ := otr.generateSMPSecondParameters(fixtureSecret(), smp1)
	assertDeepEquals(t, smp.msg.c2, fixtureMessage2().c2)
	assertDeepEquals(t, smp.msg.d2, fixtureMessage2().d2)
}

func Test_generateSMPSecondParameters_computesC3AndD3CorrectlyForOtrV2(t *testing.T) {
	otr := newOtrContext(otrV2{}, fixtureRand())
	smp1 := fixtureMessage1()
	smp, _ := otr.generateSMPSecondParameters(fixtureSecret(), smp1)
	assertDeepEquals(t, smp.msg.c3, fixtureMessage2().c3)
	assertDeepEquals(t, smp.msg.d3, fixtureMessage2().d3)
}

func Test_generateSMPSecondParameters_computesPbAndQbCorrectly(t *testing.T) {
	otr := newOtrContext(otrV2{}, fixtureRand())
	smp1 := fixtureMessage1()
	smp, _ := otr.generateSMPSecondParameters(fixtureSecret(), smp1)
	assertDeepEquals(t, smp.msg.pb, fixtureMessage2().pb)
	assertDeepEquals(t, smp.msg.qb, fixtureMessage2().qb)
}

func Test_generateSMPSecondParameters_computesCPCorrectly(t *testing.T) {
	otr := newOtrContext(otrV2{}, fixtureRand())
	smp1 := fixtureMessage1()
	smp, _ := otr.generateSMPSecondParameters(fixtureSecret(), smp1)
	assertDeepEquals(t, smp.msg.cp, fixtureMessage2().cp)
}

func Test_generateSMPSecondParameters_computesD5Correctly(t *testing.T) {
	otr := newOtrContext(otrV2{}, fixtureRand())
	smp1 := fixtureMessage1()
	smp, _ := otr.generateSMPSecondParameters(fixtureSecret(), smp1)
	assertDeepEquals(t, smp.msg.d5, fixtureMessage2().d5)
}

func Test_generateSMPSecondParameters_computesD6Correctly(t *testing.T) {
	otr := newOtrContext(otrV2{}, fixtureRand())
	smp1 := fixtureMessage1()
	smp, _ := otr.generateSMPSecondParameters(fixtureSecret(), smp1)
	assertDeepEquals(t, smp.msg.d6, fixtureMessage2().d6)
}

func Test_verifySMPSecondParameters_checkG2bForOtrV3(t *testing.T) {
	otr := newOtrContext(otrV3{}, fixtureRand())
	err := otr.verifySMPSecondParameters(fixtureSmp1(), smpMessage2{g2b: new(big.Int).SetInt64(1)})
	assertDeepEquals(t, err, errors.New("g2b is an invalid group element"))
}

func Test_verifySMPSecondParameters_checkG3bForOtrV3(t *testing.T) {
	otr := newOtrContext(otrV3{}, fixtureRand())
	err := otr.verifySMPSecondParameters(fixtureSmp1(), smpMessage2{
		g2b: new(big.Int).SetInt64(3),
		g3b: new(big.Int).SetInt64(1),
	})
	assertDeepEquals(t, err, errors.New("g3b is an invalid group element"))
}

func Test_verifySMPSecondParameters_checkPbForOtrV3(t *testing.T) {
	otr := newOtrContext(otrV3{}, fixtureRand())
	err := otr.verifySMPSecondParameters(fixtureSmp1(), smpMessage2{
		g2b: new(big.Int).SetInt64(3),
		g3b: new(big.Int).SetInt64(3),
		pb:  p,
	})
	assertDeepEquals(t, err, errors.New("Pb is an invalid group element"))
}

func Test_verifySMPSecondParameters_checkQbForOtrV3(t *testing.T) {
	otr := newOtrContext(otrV3{}, fixtureRand())
	err := otr.verifySMPSecondParameters(fixtureSmp1(), smpMessage2{
		g2b: new(big.Int).SetInt64(3),
		g3b: new(big.Int).SetInt64(3),
		pb:  pMinusTwo,
		qb:  new(big.Int).SetInt64(1),
	})
	assertDeepEquals(t, err, errors.New("Qb is an invalid group element"))
}

func Test_verifySMPSecondParameters_failsIfC2IsNotACorrectZKP(t *testing.T) {
	otr := newOtrContext(otrV3{}, fixtureRand())
	s2 := fixtureMessage2()
	s2.c2 = sub(s2.c2, big.NewInt(1))
	err := otr.verifySMPSecondParameters(fixtureSmp1(), s2)
	assertDeepEquals(t, err, errors.New("c2 is not a valid zero knowledge proof"))
}

func Test_verifySMPSecondParameters_failsIfC3IsNotACorrectZKP(t *testing.T) {
	otr := newOtrContext(otrV3{}, fixtureRand())
	s2 := fixtureMessage2()
	s2.c3 = sub(s2.c3, big.NewInt(1))
	err := otr.verifySMPSecondParameters(fixtureSmp1(), s2)
	assertDeepEquals(t, err, errors.New("c3 is not a valid zero knowledge proof"))
}

func Test_verifySMPSecondParameters_failsIfCpIsNotACorrectZKP(t *testing.T) {
	otr := newOtrContext(otrV3{}, fixtureRand())
	s2 := fixtureMessage2()
	s2.cp = sub(s2.cp, big.NewInt(1))
	err := otr.verifySMPSecondParameters(fixtureSmp1(), s2)
	assertDeepEquals(t, err, errors.New("cP is not a valid zero knowledge proof"))
}

func Test_verifySMPSecondParameters_succeedsForACorrectZKP(t *testing.T) {
	otr := newOtrContext(otrV3{}, fixtureRand())
	err := otr.verifySMPSecondParameters(fixtureSmp1(), fixtureMessage2())
	assertDeepEquals(t, err, nil)
}
