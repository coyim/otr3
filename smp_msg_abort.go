package otr3

type smpMessageAbort struct{}

func (m smpMessageAbort) tlv() []byte {
	return genSMPTLV(6)
}
