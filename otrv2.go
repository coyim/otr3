package otr3

type otrV2 struct{}

func (v otrV2) parameterLength() int {
	return 16
}
