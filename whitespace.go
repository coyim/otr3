package otr3

import "bytes"

var (
	whitespaceTagHeader = []byte{
		0x20, 0x09, 0x20, 0x20, 0x09, 0x09, 0x09, 0x09,
		0x20, 0x09, 0x20, 0x09, 0x20, 0x09, 0x20, 0x20,
	}
)

func genWhitespaceTag(p policies) []byte {
	ret := whitespaceTagHeader

	if p.has(allowV2) {
		ret = append(ret, otrV2{}.whitespaceTag()...)
	}

	if p.has(allowV3) {
		ret = append(ret, otrV3{}.whitespaceTag()...)
	}

	return ret
}

func (c *Conversation) appendWhitespaceTag(message []byte) []byte {
	if !c.Policies.has(sendWhitespaceTag) || c.stopSendingWhitespaceTags {
		return message
	}

	return append(message, genWhitespaceTag(c.Policies)...)
}

func (c *Conversation) processWhitespaceTag(message []byte) (plain, toSend []byte, err error) {
	wsPos := bytes.Index(message, whitespaceTagHeader)
	if wsPos == -1 {
		plain = message
		return
	}

	plain = message[:wsPos]

	if !c.Policies.has(whitespaceStartAKE) {
		return
	}

	toSend, err = c.startAKEFromWhitespaceTag(message[wsPos:])

	return
}

func (c *Conversation) startAKEFromWhitespaceTag(tag []byte) (toSend messageWithHeader, err error) {
	switch {
	case c.Policies.has(allowV3) && bytes.Contains(tag, otrV3{}.whitespaceTag()):
		c.version = otrV3{}
	case c.Policies.has(allowV2) && bytes.Contains(tag, otrV2{}.whitespaceTag()):
		c.version = otrV2{}
	default:
		err = errInvalidVersion
		return
	}

	return c.potentialAuthError(c.sendDHCommit())
}
