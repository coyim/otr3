package otr3

import (
	"errors"
	"math/big"
	"testing"
)

func Test_generateSMPFourthParameters_generatesLongerValuesForR7WithProtocolV3(t *testing.T) {
	otr := context{otrV3{}, fixtureRand()}
	smp := otr.generateSMPFourthParameters(fixtureSecret(), fixtureSmp2(), fixtureMessage3())
	assertDeepEquals(t, smp.r7, fixtureLong1)
}

func Test_generateSMPFourthParameters_generatesShorterValuesForR7WithProtocolV3(t *testing.T) {
	otr := context{otrV2{}, fixtureRand()}
	smp := otr.generateSMPFourthParameters(fixtureSecret(), fixtureSmp2(), fixtureMessage3())
	assertDeepEquals(t, smp.r7, fixtureShort1)
}

func Test_generateSMPFourthParameters_computesRbCorrectly(t *testing.T) {
	otr := context{otrV2{}, fixtureRand()}
	smp := otr.generateSMPFourthParameters(fixtureSecret(), fixtureSmp2(), fixtureMessage3())
	assertDeepEquals(t, smp.msg.rb, fixtureMessage4().rb)
}

func Test_generateSMPFourthParameters_computesCrCorrectly(t *testing.T) {
	otr := context{otrV2{}, fixtureRand()}
	smp := otr.generateSMPFourthParameters(fixtureSecret(), fixtureSmp2(), fixtureMessage3())
	assertDeepEquals(t, smp.msg.cr, fixtureMessage4().cr)
}

func Test_generateSMPFourthParameters_computesD7Correctly(t *testing.T) {
	otr := context{otrV2{}, fixtureRand()}
	smp := otr.generateSMPFourthParameters(fixtureSecret(), fixtureSmp2(), fixtureMessage3())
	assertDeepEquals(t, smp.msg.d7, fixtureMessage4().d7)
}

func Test_verifySMP4Parameters_succeedsForValidZKPS(t *testing.T) {
	otr := context{otrV3{}, fixtureRand()}
	err := otr.verifySMP4Parameters(fixtureSmp3(), fixtureMessage2(), fixtureMessage4())
	assertDeepEquals(t, err, nil)
}

func Test_verifySMP4Parameters_failsIfRbIsNotInTheGroupForProtocolV3(t *testing.T) {
	otr := context{otrV3{}, fixtureRand()}
	err := otr.verifySMP4Parameters(fixtureSmp3(), fixtureMessage2(), smpMessage4{rb: big.NewInt(1)})
	assertDeepEquals(t, err, errors.New("Rb is an invalid group element"))
}

func Test_verifySMP4Parameters_failsIfCrIsNotACorrectZKP(t *testing.T) {
	otr := context{otrV3{}, fixtureRand()}
	m := fixtureMessage4()
	m.cr = sub(m.cr, big.NewInt(1))
	err := otr.verifySMP4Parameters(fixtureSmp3(), fixtureMessage2(), m)
	assertDeepEquals(t, err, errors.New("cR is not a valid zero knowledge proof"))
}