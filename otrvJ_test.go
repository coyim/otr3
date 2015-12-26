package otr3

import "testing"

func Test_otrVJ_messageHeader_generatesCorrectVersion(t *testing.T) {
	c := &Conversation{version: otrVJ{}}
	c.theirInstanceTag = 0x100
	c.ourInstanceTag = 0x122

	v, err := otrVJ{}.messageHeader(c, msgTypeDHCommit)

	assertEquals(t, err, nil)
	assertDeepEquals(t, v, []byte{0xfe, 0x32, 0x02, 0x0, 0x0, 0x1, 0x22, 0x0, 0x0, 0x1, 0x0})
}

func Test_otrVJ_whitespaceTag_generatesACorrectTag(t *testing.T) {
	v := otrVJ{}.whitespaceTag()

	assertDeepEquals(t, v, []byte{0x20, 0x9, 0x20, 0x20, 0x9, 0x20, 0x9, 0x20})
}
