package otr3

type policies map[policy]bool

type policy int

const (
	allowV1 policy = iota
	allowV2
	allowV3
	requireEncryption
	sendWhitespaceTag
	whitespaceStartAke
	errorStartAke
)

func (p policies) has(c policy) bool {
	_, ok := p[c]
	return ok
}

func (p policies) addPolicy(c policy) {
	p[c] = true
}

func (p policies) allowV1() {
	p.addPolicy(allowV1)
}

func (p policies) allowV2() {
	p.addPolicy(allowV2)
}

func (p policies) allowV3() {
	p.addPolicy(allowV3)
}

func (p policies) requireEncryption() {
	p.addPolicy(requireEncryption)
}

func (p policies) sendWhitespaceTag() {
	p.addPolicy(sendWhitespaceTag)
}

func (p policies) whitespaceStartAKE() {
	p.addPolicy(whitespaceStartAke)
}

func (p policies) errorStartAKE() {
	p.addPolicy(errorStartAke)
}
