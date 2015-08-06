package otr3

import "bytes"

var (
	// Maps to OTRL_MESSAGE_TAG_BASE
	whitespaceTagHeader = []byte(" \t  \t\t\t\t \t \t \t  ")
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

func (c *Conversation) processWhitespaceTag(message ValidMessage) (plain MessagePlaintext, toSend []messageWithHeader, err error) {
	wsPos := bytes.Index(message, whitespaceTagHeader)

	plain = MessagePlaintext(message[:wsPos])

	var restPlain MessagePlaintext
	restPlain, toSend, err = c.startAKEFromWhitespaceTag(message[(wsPos + len(whitespaceTagHeader)):])

	plain = append(plain, restPlain...)

	if !c.Policies.has(whitespaceStartAKE) {
		toSend = nil
		err = nil
		return
	}
	return
}

func nextAllWhite(data []byte) (allwhite []byte, rest []byte, hasAllWhite bool) {
	if len(data) < 8 {
		return nil, data, false
	}

	for i := 0; i < 8; i++ {
		if data[i] != ' ' && data[i] != '\t' {
			return nil, data, false
		}
	}

	return data[0:8], data[8:], true
}

func (c *Conversation) startAKEFromWhitespaceTag(tag []byte) (restPlain MessagePlaintext, toSend []messageWithHeader, err error) {
	versions := 0

	currentData := tag
	for {
		aw, r, has := nextAllWhite(currentData)
		if !has {
			break
		}
		currentData = r
		if bytes.Equal(aw, otrV3{}.whitespaceTag()) {
			versions |= (1 << 3)
		} else if bytes.Equal(aw, otrV2{}.whitespaceTag()) {
			versions |= (1 << 2)
		}
	}

	restPlain = currentData
	switch {
	case c.Policies.has(allowV3) && versions&(1<<3) > 0:
		c.version = otrV3{}
	case c.Policies.has(allowV2) && versions&(1<<2) > 0:
		c.version = otrV2{}
	default:
		err = errInvalidVersion
		return
	}
	ts, e := c.sendDHCommit()
	toSend, err = c.potentialAuthError(compactMessagesWithHeader(ts), e)
	return
}
