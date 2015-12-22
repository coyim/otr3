package otr3

import "testing"

func Test_otrv3x_messageHeader_generatesCorrectVersion(t *testing.T) {
	c := &Conversation{version: otrV3X{}}
	c.theirInstanceTag = 0x100
	c.ourInstanceTag = 0x122

	v, err := otrV3X{}.messageHeader(c, msgTypeDHCommit)

	assertEquals(t, err, nil)
	assertDeepEquals(t, v, []byte{0x00, 0x04, 0x02, 0x0, 0x0, 0x1, 0x22, 0x0, 0x0, 0x1, 0x0})
}
