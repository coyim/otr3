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

func (p *policies) add(c policy) {
	*p = policies(int(*p) | int(c))
}

func (p *policies) allowV1() {
	p.add(allowV1)
}

func (p *policies) allowV2() {
	p.add(allowV2)
}

func (p *policies) allowV3() {
	p.add(allowV3)
}

func (p *policies) requireEncryption() {
	p.add(requireEncryption)
}

func (p *policies) sendWhitespaceTag() {
	p.add(sendWhitespaceTag)
}

func (p *policies) whitespaceStartAKE() {
	p.add(whitespaceStartAke)
}

func (p *policies) errorStartAKE() {
	p.add(errorStartAke)
}
