package otr3

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math/big"
)

var otrv3FragmentationPrefix = []byte("?OTR|")

const (
	otrv3HeaderLen      = 11
	minValidInstanceTag = uint32(0x100)
)

type otrV3 struct{}

func (v otrV3) parameterLength() int {
	return 192
}

func (v otrV3) isGroupElement(n *big.Int) bool {
	return isGroupElement(n)
}

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

func (v otrV3) messageHeader(c *Conversation, msgType byte) ([]byte, error) {
	if err := generateInstanceTag(c); err != nil {
		return nil, err
	}

	out := appendShort(nil, v.protocolVersion())
	out = append(out, msgType)
	out = appendWord(out, c.ourInstanceTag)
	out = appendWord(out, c.theirInstanceTag)
	return out, nil
}

func generateInstanceTag(c *Conversation) error {
	if c.ourInstanceTag != 0 {
		return nil
	}

	var ret uint32
	var dst [4]byte

	for ret < minValidInstanceTag {
		if err := c.randomInto(dst[:]); err != nil {
			return err
		}

		ret = binary.BigEndian.Uint32(dst[:])
	}

	c.ourInstanceTag = ret

	return nil
}

func (v otrV3) parseMessageHeader(c *Conversation, msg []byte) ([]byte, []byte, error) {
	if len(msg) < otrv3HeaderLen {
		return nil, nil, errInvalidOTRMessage
	}
	header := msg[:otrv3HeaderLen]

	msg, senderInstanceTag, _ := extractWord(msg[messageHeaderPrefix:])
	msg, receiverInstanceTag, _ := extractWord(msg)

	if c.theirInstanceTag == 0 {
		c.theirInstanceTag = senderInstanceTag
	}

	if receiverInstanceTag > 0 && receiverInstanceTag < minValidInstanceTag {
		return nil, nil, errInvalidOTRMessage
	}

	if senderInstanceTag < minValidInstanceTag {
		return nil, nil, errInvalidOTRMessage
	}

	if receiverInstanceTag != 0 && c.ourInstanceTag != receiverInstanceTag {
		return nil, nil, errReceivedMessageForOtherInstance
	}

	if senderInstanceTag >= minValidInstanceTag && c.theirInstanceTag != senderInstanceTag {
		return nil, nil, errReceivedMessageForOtherInstance
	}

	return header, msg, nil
}
