package otr3

import "bytes"

var (
	whitespaceTagHeader = []byte{
		0x20, 0x09, 0x20, 0x20, 0x09, 0x09, 0x09, 0x09,
		0x20, 0x09, 0x20, 0x09, 0x20, 0x09, 0x20, 0x20,
	}
)

func genWhitespaceTag(p policies) []byte {
	ret := make([]byte, 16)

	copy(ret[:], whitespaceTagHeader)

	if p.has(allowV2) {
		ret = append(ret, otrV2{}.whitespaceTag()...)
	}

	if p.has(allowV3) {
		ret = append(ret, otrV3{}.whitespaceTag()...)
	}

	return ret
}

func (c *Conversation) appendWhitespaceTag(message []byte) []byte {
	//TODO: stop sending after receiving a plaintext (nonDH-Commit) message
	if !c.policies.has(sendWhitespaceTag) {
		return message
	}

	return append(message, genWhitespaceTag(c.policies)...)
}

func (c *Conversation) processWhitespaceTag(message []byte) (ret, toSend []byte, err error) {
	wsPos := bytes.Index(message, whitespaceTagHeader)
	if wsPos == -1 {
		ret = message
		return
	}

	ret = message[:wsPos]

	if !c.policies.has(whitespaceStartAKE) {
		return
	}

	toSend, err = c.startAKEFromWhitespaceTag(message[wsPos:])

	return
}

func (c *Conversation) startAKEFromWhitespaceTag(tag []byte) (toSend []byte, err error) {
	switch {
	case c.policies.has(allowV3) && bytes.Contains(tag, otrV3{}.whitespaceTag()):
		c.version = otrV3{}
	case c.policies.has(allowV2) && bytes.Contains(tag, otrV2{}.whitespaceTag()):
		c.version = otrV2{}
	default:
		err = errInvalidVersion
		return
	}

	toSend, err = c.sendDHCommit()

	return
}
