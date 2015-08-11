package otr3

import "testing"

func Test_policies_requireEncryption_addsRequirementOfEncryption(t *testing.T) {
	p := policies(0)
	p.RequireEncryption()
	assertEquals(t, p.has(requireEncryption), true)
}

func Test_policies_sendWhitespaceTag_addsPolicyForSendingWhitespaceTag(t *testing.T) {
	p := policies(0)
	p.SendWhitespaceTag()
	assertEquals(t, p.has(sendWhitespaceTag), true)
}

func Test_policies_whitespaceStartAKE_addsWhitespaceStartAKEPolicy(t *testing.T) {
	p := policies(0)
	p.WhitespaceStartAKE()
	assertEquals(t, p.has(whitespaceStartAKE), true)
}

func Test_policies_errorStartAKE_addsErrorStartAKEPolicy(t *testing.T) {
	p := policies(0)
	p.ErrorStartAKE()
	assertEquals(t, p.has(errorStartAKE), true)
}
