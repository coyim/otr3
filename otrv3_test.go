package otr3

import "testing"

func Test_parseMessageHeader_ignoresBadReceiverInstanceTagInDHCommitMessages(t *testing.T) {
	v := otrV3{}
	c := &Conversation{version: v}
	c.ourInstanceTag = 0

	sender := fixtureConversation()
	sender.theirInstanceTag = 0
	m, _ := sender.messageHeader(msgTypeDHCommit)

	_, _, err := v.parseMessageHeader(c, m)

	assertEquals(t, err, nil)
}

func Test_parseMessageHeader_returnsErrorWhenReceiverInstanceTagIsLesserThan0x100(t *testing.T) {
	v := otrV3{}
	c := &Conversation{version: v}

	sender := fixtureConversation()
	sender.theirInstanceTag = 0x99
	m, _ := sender.messageHeader(msgTypeDHCommit)

	_, _, err := v.parseMessageHeader(c, m)

	assertEquals(t, err, errInvalidOTRMessage)
}

func Test_parseMessageHeader_returnsErrorWhenSenderInstanceTagIsLesserThan0x100(t *testing.T) {
	v := otrV3{}
	c := &Conversation{version: v}

	sender := fixtureConversation()
	sender.ourInstanceTag = 0x99
	m, _ := sender.messageHeader(msgTypeDHCommit)

	_, _, err := v.parseMessageHeader(c, m)

	assertEquals(t, err, errInvalidOTRMessage)

	sender.ourInstanceTag = 0
	m, _ = sender.messageHeader(msgTypeDHCommit)
	copy(m[3:6], []byte{0, 0, 0, 0}) //Forces receiving a msg with senderInstanceTag = 0
	_, _, err = v.parseMessageHeader(c, m)

	assertEquals(t, err, errInvalidOTRMessage)
}

func Test_parseMessageHeader_acceptsReceiverInstanceTagEqualsZero(t *testing.T) {
	v := otrV3{}
	c := &Conversation{version: v}

	sender := fixtureConversation()
	sender.theirInstanceTag = 0
	m, _ := sender.messageHeader(msgTypeDHCommit)

	_, _, err := v.parseMessageHeader(c, m)

	assertEquals(t, err, nil)
}
func Test_parseMessageHeader_returnsErrorWhenOurInstanceDoesNotMatchReceiverInstanceTag(t *testing.T) {
	v := otrV3{}
	c := &Conversation{version: v}
	c.ourInstanceTag = 0x122

	sender := fixtureConversation()
	sender.theirInstanceTag = 0x111
	m, _ := sender.messageHeader(msgTypeDHCommit)

	_, _, err := v.parseMessageHeader(c, m)

	assertEquals(t, err, errReceivedMessageForOtherInstance)
}

func Test_otrv3_parseMessageHeader_signalsMalformedMessageWhenWeCantParseInstanceTags(t *testing.T) {
	v := otrV3{}
	c := &Conversation{version: v}

	c.expectMessageEvent(t, func() {
		v.parseMessageHeader(c, []byte{0x00, 0x03, 0x02, 0x00, 0x00, 0x01, 0x22, 0x00, 0x00, 0x01})
	}, MessageEventReceivedMessageMalformed, nil, nil)
}

func Test_otrv3_parseMessageHeader_signalsMalformedMessageWhenWeTheirInstanceTagIsTooLow(t *testing.T) {
	v := otrV3{}
	c := &Conversation{version: v}

	c.expectMessageEvent(t, func() {
		v.parseMessageHeader(c, []byte{0x00, 0x03, 0x02, 0x00, 0x00, 0x00, 0x22, 0x00, 0x00, 0x01, 0x01})
	}, MessageEventReceivedMessageMalformed, nil, nil)
}

func Test_parseMessageHeader_returnsErrorWhenTheirInstanceTagDoesNotMatchSenderInstanceTag(t *testing.T) {
	v := otrV3{}
	c := &Conversation{version: v}
	c.theirInstanceTag = 0x122

	sender := fixtureConversation()
	sender.ourInstanceTag = 0x111
	m, _ := sender.messageHeader(msgTypeDHCommit)

	_, _, err := v.parseMessageHeader(c, m)

	assertEquals(t, err, errReceivedMessageForOtherInstance)
}

func Test_generateInstanceTag_generatesOurInstanceTag(t *testing.T) {
	rand := fixedRand([]string{"00000099", "00001234"})
	c := &Conversation{Rand: rand}

	err := c.generateInstanceTag()

	assertEquals(t, err, nil)
	assertEquals(t, c.ourInstanceTag, uint32(0x1234))
}

func Test_generateInstanceTag_returnsAnErrorIfFailsToReadFromRand(t *testing.T) {
	rand := fixedRand([]string{"00000099", "00000080"})
	c := &Conversation{Rand: rand}

	err := c.generateInstanceTag()

	assertEquals(t, err, errShortRandomRead)
	assertEquals(t, c.ourInstanceTag, uint32(0))
}

func Test_messageHeader_generatesOurInstanceTagLazily(t *testing.T) {
	c := &Conversation{}

	_, err := otrV3{}.messageHeader(c, msgTypeDHCommit)

	assertEquals(t, err, nil)
	assertEquals(t, c.ourInstanceTag < minValidInstanceTag, false)

	previousInstanceTag := c.ourInstanceTag

	_, err = otrV3{}.messageHeader(c, msgTypeDHCommit)
	assertEquals(t, err, nil)
	assertEquals(t, c.ourInstanceTag, previousInstanceTag)
}

func Test_parseMessageHeader_savesTheirInstanceTag(t *testing.T) {
	z := uint32(0)
	v := otrV3{}
	c := &Conversation{}
	m := fixtureDHCommitMsg()

	assertEquals(t, c.theirInstanceTag, z)

	_, _, err := v.parseMessageHeader(c, m)

	assertEquals(t, err, nil)

	assertEquals(t, c.theirInstanceTag != z, true)
}
