package otr3

import (
	"bytes"
	"fmt"
	"math/big"
)

type otrV3 struct{}

func (v otrV3) parameterLength() int {
	return 192
}

func (v otrV3) isGroupElement(n *big.Int) bool {
	return isGroupElement(n)
}

var otrv3FragmentationPrefix = []byte("?OTR|")

const otrv3HeaderLen = 11

func (v otrV3) isFragmented(data []byte) bool {
	return bytes.HasPrefix(data, otrv3FragmentationPrefix) || otrV2{}.isFragmented(data)
}

func (v otrV3) fragmentPrefix(n, total int, itags uint32, itagr uint32) []byte {
	return []byte(fmt.Sprintf("%s%08x|%08x,%05d,%05d,", string(otrv3FragmentationPrefix), itags, itagr, n+1, total))
}

func (v otrV3) minFragmentSize() uint16 {
	//TODO: need to double check
	return 26
}

func (v otrV3) protocolVersion() uint16 {
	return 3
}

func (v otrV3) whitespaceTag() []byte {
	return []byte{
		0x20, 0x20, 0x09, 0x09, 0x20, 0x20, 0x09, 0x09,
	}
}

func (v otrV3) messageHeader(c *Conversation, msgType byte) []byte {
	out := appendShort(nil, v.protocolVersion())
	out = append(out, msgType)
	out = appendWord(out, c.ourInstanceTag)
	out = appendWord(out, c.theirInstanceTag)
	return out
}

func generateInstanceTag() uint32 {
	//TODO generate this
	return 0x00000100 + 0x01
}

//TODO: unit test
func (v otrV3) parseMessageHeader(c *Conversation, msg []byte) ([]byte, error) {
	if len(msg) < otrv3HeaderLen {
		return nil, errInvalidOTRMessage
	}

	msgType := msg[2]

	msg, senderInstanceTag, _ := extractWord(msg[messageHeaderPrefix:])
	msg, receiverInstanceTag, _ := extractWord(msg)

	//NOTE: I'm afraid of doing this as part of this method. Instance tags
	//initialization should be done at specific places (and this method is called
	//both on the ake state machine and when receiving data messages)
	//ourInstanceTag should be initialized before generating the DHCommit/DHKey msg
	//theirInstanceTag should be initialized when the DHCommit/DHKey msg is received
	//TODO: double check if instance tags are initialized in all the places
	if c.ourInstanceTag == 0 {
		c.ourInstanceTag = generateInstanceTag()
	}

	if c.theirInstanceTag == 0 {
		c.theirInstanceTag = senderInstanceTag
	}

	if msgType != msgTypeDHCommit && (receiverInstanceTag < 0x100 || c.ourInstanceTag != receiverInstanceTag) {
		return nil, errReceivedMessageForOtherInstance
	}

	if senderInstanceTag < 0x100 || c.theirInstanceTag != senderInstanceTag {
		return nil, errReceivedMessageForOtherInstance
	}

	return msg, nil
}
