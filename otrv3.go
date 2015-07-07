package otr3

type otrV3 struct{}

func (v otrV3) parameterLength() int {
	return 192
}
