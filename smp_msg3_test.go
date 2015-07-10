package otr3

import (
	"errors"
	"math/big"
	"testing"
)

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

func Test_generateSMPThirdParameters_computesPaPbCorrectly(t *testing.T) {
	otr := context{otrV2{}, fixtureRand()}
	smp := otr.generateSMPThirdParameters(fixtureSecret(), fixtureSmp1(), fixtureMessage2())
	assertDeepEquals(t, smp.papb, fixtureSmp3().papb)
}

func Test_generateSMPThirdParameters_computesQaQbCorrectly(t *testing.T) {
	otr := context{otrV2{}, fixtureRand()}
	smp := otr.generateSMPThirdParameters(fixtureSecret(), fixtureSmp1(), fixtureMessage2())
	assertDeepEquals(t, smp.qaqb, fixtureSmp3().qaqb)
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
	err := otr.verifySMP3Parameters(smpMessage3{pa: big.NewInt(1)}, fixtureSmp2())
	assertDeepEquals(t, err, errors.New("Pa is an invalid group element"))
}

func Test_verifySMP3Parameters_failsIfQaIsNotInTheGroupForProtocolV3(t *testing.T) {
	otr := context{otrV3{}, fixtureRand()}
	err := otr.verifySMP3Parameters(smpMessage3{
		pa: big.NewInt(2),
		qa: big.NewInt(1),
	}, fixtureSmp2())
	assertDeepEquals(t, err, errors.New("Qa is an invalid group element"))
}

func Test_verifySMP3Parameters_failsIfRaIsNotInTheGroupForProtocolV3(t *testing.T) {
	otr := context{otrV3{}, fixtureRand()}
	err := otr.verifySMP3Parameters(smpMessage3{
		pa: big.NewInt(2),
		qa: big.NewInt(2),
		ra: big.NewInt(1),
	}, fixtureSmp2())
	assertDeepEquals(t, err, errors.New("Ra is an invalid group element"))
}

func Test_verifySMP3Parameters_succeedsForValidZKPS(t *testing.T) {
	otr := context{otrV3{}, fixtureRand()}
	err := otr.verifySMP3Parameters(fixtureMessage3(), fixtureSmp2())
	assertDeepEquals(t, err, nil)
}

func Test_verifySMP3Parameters_failsIfCpIsNotAValidZKP(t *testing.T) {
	otr := context{otrV2{}, fixtureRand()}
	m := fixtureMessage3()
	m.cp = sub(m.cp, big.NewInt(1))
	err := otr.verifySMP3Parameters(m, fixtureSmp2())
	assertDeepEquals(t, err, errors.New("cP is not a valid zero knowledge proof"))
}

func Test_verifySMP3Parameters_failsIfCrIsNotAValidZKP(t *testing.T) {
	otr := context{otrV2{}, fixtureRand()}
	m := fixtureMessage3()
	m.cr = sub(m.cr, big.NewInt(1))
	err := otr.verifySMP3Parameters(m, fixtureSmp2())
	assertDeepEquals(t, err, errors.New("cR is not a valid zero knowledge proof"))
}
