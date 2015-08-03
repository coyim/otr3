package otr3

import "testing"

func Test_parseMessageHeader_ignoresBadReceiverInstanceTagInDHCommitMessages(t *testing.T) {
	v := otrV3{}
	c := &Conversation{version: v}
	c.ourInstanceTag = 0

	sender := fixtureConversation()
	sender.theirInstanceTag = 0
	m, _ := sender.dhCommitMessage()

	_, _, err := v.parseMessageHeader(c, m)

	assertEquals(t, err, nil)
}

func Test_parseMessageHeader_returnsErrorWhenReceiverInstanceTagIsLesserThan0x100(t *testing.T) {
	v := otrV3{}
	c := &Conversation{version: v}

	sender := fixtureConversation()
	sender.theirInstanceTag = 0x99
	m, _ := sender.dhKeyMessage()

	_, _, err := v.parseMessageHeader(c, m)

	assertEquals(t, err, errInvalidOTRMessage)
}

func Test_parseMessageHeader_returnsErrorWhenSenderInstanceTagIsLesserThan0x100(t *testing.T) {
	v := otrV3{}
	c := &Conversation{version: v}

	sender := fixtureConversation()
	sender.ourInstanceTag = 0x99
	m, _ := sender.dhKeyMessage()

	_, _, err := v.parseMessageHeader(c, m)

	assertEquals(t, err, errInvalidOTRMessage)

	sender.ourInstanceTag = 0
	m, _ = sender.dhKeyMessage()
	_, _, err = v.parseMessageHeader(c, m)

	assertEquals(t, err, errInvalidOTRMessage)
}

func Test_parseMessageHeader_acceptsReceiverInstanceTagEqualsZero(t *testing.T) {
	v := otrV3{}
	c := &Conversation{version: v}

	sender := fixtureConversation()
	sender.theirInstanceTag = 0
	m, _ := sender.dhKeyMessage()

	_, _, err := v.parseMessageHeader(c, m)

	assertEquals(t, err, nil)
}
func Test_parseMessageHeader_returnsErrorWhenOurInstanceDoesNotMatchReceiverInstanceTag(t *testing.T) {
	v := otrV3{}
	c := &Conversation{version: v}
	c.ourInstanceTag = 0x122

	sender := fixtureConversation()
	sender.theirInstanceTag = 0x111
	m, _ := sender.dhKeyMessage()

	_, _, err := v.parseMessageHeader(c, m)

	assertEquals(t, err, errReceivedMessageForOtherInstance)
}

func Test_parseMessageHeader_returnsErrorWhenTheirInstanceTagDoesNotMatchSenderInstanceTag(t *testing.T) {
	v := otrV3{}
	c := &Conversation{version: v}
	c.theirInstanceTag = 0x122

	sender := fixtureConversation()
	sender.ourInstanceTag = 0x111
	m, _ := sender.dhCommitMessage()

	_, _, err := v.parseMessageHeader(c, m)

	assertEquals(t, err, errReceivedMessageForOtherInstance)
}

func Test_parseMessageHeader_generatesOurInstanceTag(t *testing.T) {
	z := uint32(0)
	v := otrV3{}
	c := &Conversation{}
	m := fixtureDHCommitMsg()

	assertEquals(t, c.ourInstanceTag, z)

	_, _, err := v.parseMessageHeader(c, m)

	assertEquals(t, err, nil)
	assertEquals(t, c.ourInstanceTag != z, true)
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
