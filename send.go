package otr3

import (
	"encoding/base64"
	"errors"
)

func (c *Conversation) Send(msg []byte) ([][]byte, error) {
	if !c.Policies.isOTREnabled() {
		return [][]byte{msg}, nil
	}
	switch c.msgState {
	case plainText:
		if c.Policies.has(requireEncryption) {
			return [][]byte{c.queryMessage()}, nil
		}
		if c.Policies.has(sendWhitespaceTag) {
			msg = c.appendWhitespaceTag(msg)
		}
		return [][]byte{msg}, nil
	case encrypted:
		dataMsg, _ := c.genDataMsg(msg)
		toSend, err := c.wrapMessageHeader(msgTypeData, dataMsg.serialize())
		if err != nil {
			return nil, err
		}
		return c.encode(toSend), nil
	case finished:
		return nil, errors.New("otr: cannot send message because secure conversation has finished")
	}

	return nil, errors.New("otr: cannot send message in current state")
}

func (c *Conversation) encode(msg []byte) [][]byte {
	b64 := make([]byte, base64.StdEncoding.EncodedLen(len(msg))+len(msgMarker)+1)
	base64.StdEncoding.Encode(b64[len(msgMarker):], msg)
	copy(b64, msgMarker)
	b64[len(b64)-1] = '.'

	bytesPerFragment := c.fragmentSize - c.version.minFragmentSize()
	return c.fragment(b64, bytesPerFragment, uint32(0), uint32(0))
}

func (c *Conversation) sendDHCommit() (toSend []byte, err error) {
	toSend, err = c.dhCommitMessage()
	if err != nil {
		return
	}
	toSend, err = c.wrapMessageHeader(msgTypeDHCommit, toSend)
	if err != nil {
		return nil, err
	}

	c.ake.state = authStateAwaitingDHKey{}
	//TODO: wipe keys from the memory
	c.keys = keyManagementContext{
		oldMACKeys: c.keys.oldMACKeys,
	}
	return
}
