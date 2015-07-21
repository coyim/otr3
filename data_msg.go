package otr3

import "math/big"

func (c *otrContext) genDataMsg(tlvs ...[]byte) []byte {
	var out []byte

	out = appendShort(out, c.protocolVersion())
	out = append(out, msgTypeData)

	//TODO
	if c.needInstanceTag() {
		out = appendWord(out, uint32(0))
		out = appendWord(out, uint32(0))
	}

	//TODO: implement IGNORE_UNREADABLE
	out = append(out, 0x00)

	//TODO after key management
	ourKeyID := uint32(0)
	theirKeyID := uint32(0)
	out = appendWord(out, ourKeyID)
	out = appendWord(out, theirKeyID)

	//TODO after key management
	dhy := big.NewInt(0)
	out = appendMPI(out, dhy)

	//TODO
	var crt [8]byte
	out = append(out, crt[:]...)

	//tlv is properly formatted
	var data []byte
	for _, tlv := range tlvs {
		data = append(data, tlv...)
	}

	//TODO encrypt
	out = append(out, data...)

	//TODO Authenticator (MAC)
	//TODO Old MAC keys to be revealed (DATA)

	return out
}