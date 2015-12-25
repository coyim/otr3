package otr3

import (
	"bytes"
	"errors"
	"fmt"
	"hash"
	"math/big"
	"strconv"
)

type otrVersion interface {
	protocolVersion() string
	protocolVersionNumber() uint16
	parameterLength() int
	isGroupElement(n *big.Int) bool
	isFragmented(data []byte) bool
	parseFragmentPrefix(c *Conversation, data []byte) (rest []byte, ignore bool, ok bool)
	fragmentPrefix(n, total int, itags uint32, itagr uint32) []byte
	whitespaceTag() []byte
	messageHeader(c *Conversation, msgType byte) ([]byte, error)
	parseMessageHeader(c *Conversation, msg []byte) ([]byte, []byte, error)
	hash([]byte) []byte
	hashInstance() hash.Hash
	hashLength() int
	hash2([]byte) []byte
	hash2Instance() hash.Hash
	hash2Length() int
	truncateLength() int
	keyLength() int
}

func newOtrVersion(v uint16, p policies) (version otrVersion, err error) {
	toCheck := policy(0)
	switch v {
	case otrV2{}.protocolVersionNumber():
		version = otrV2{}
		toCheck = allowV2
	case otrV3{}.protocolVersionNumber():
		version = otrV3{}
		toCheck = allowV3
	case otrVJ{}.protocolVersionNumber():
		version = otrVJ{}
		toCheck = allowVExtensionJ
	default:
		return nil, errUnsupportedOTRVersion
	}
	if !p.has(toCheck) {
		return nil, errInvalidVersion
	}
	return
}

func versionFromFragment(fragment []byte) string {
	switch {
	case bytes.HasPrefix(fragment, otrv3FragmentationPrefix):
		return "3"
	case bytes.HasPrefix(fragment, otrv2FragmentationPrefix):
		return "2"
	}

	return ""
}

func versionStringFrom(v uint16) string {
	if v >= 65000 {
		return fmt.Sprintf("%c", v-65000)
	}
	return strconv.Itoa(int(v))
}

func (c *Conversation) checkVersion(message []byte) (err error) {
	_, messageVersion, ok := extractShort(message)
	if !ok {
		return errInvalidOTRMessage
	}

	if err := c.commitToVersionFrom(set(versionStringFrom(messageVersion))); err != nil {
		return err
	}

	if c.version.protocolVersionNumber() != messageVersion {
		return errWrongProtocolVersion
	}

	return nil
}

func (c *Conversation) decideOnVersionFrom(versions map[string]bool) (otrVersion, error) {
	if c.version != nil {
		return nil, nil
	}

	var version otrVersion

	switch {
	case c.Policies.has(allowVExtensionJ) && versions["J"]:
		version = otrVJ{}
	case c.Policies.has(allowV3) && versions["3"]:
		version = otrV3{}
	case c.Policies.has(allowV2) && versions["2"]:
		version = otrV2{}
	default:
		return nil, errUnsupportedOTRVersion
	}

	return version, nil
}

// Based on the policy, commit to a version given a set of versions offered by the other peer unless the conversation has already committed to a version.
func (c *Conversation) commitToVersionFrom(versions map[string]bool) error {
	vv, ee := c.decideOnVersionFrom(versions)

	if ee != nil {
		return ee
	}

	if vv == nil {
		return nil
	}

	c.version = vv

	return c.setKeyMatchingVersion()
}

func (c *Conversation) setKeyMatchingVersion() error {
	for _, k := range c.ourKeys {
		if k.IsAvailableForVersion(c.version.protocolVersionNumber()) {
			c.ourCurrentKey = k
			return nil
		}
	}

	return errors.New("no possible key for current version")
}
