package otr3

type policies int

type policy int

const (
	allowV1 policy = 1 << iota
	allowV2
	allowV3
	requireEncryption
	sendWhitespaceTag
	whitespaceStartAke
	errorStartAke
)

func (p *policies) has(c policy) bool {
	return int(*p)&int(c) == int(c)
}

func (p *policies) addPolicy(c policy) {
	*p = policies(int(*p) | int(c))
}

func (p *policies) allowV1() {
	p.addPolicy(allowV1)
}

func (p *policies) allowV2() {
	p.addPolicy(allowV2)
}

func (p *policies) allowV3() {
	p.addPolicy(allowV3)
}

func (p *policies) requireEncryption() {
	p.addPolicy(requireEncryption)
}

func (p *policies) sendWhitespaceTag() {
	p.addPolicy(sendWhitespaceTag)
}

func (p *policies) whitespaceStartAKE() {
	p.addPolicy(whitespaceStartAke)
}

func (p *policies) errorStartAKE() {
	p.addPolicy(errorStartAke)
}
