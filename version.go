package otr3

import "math/big"

type otrVersion interface {
	protocolVersion() uint16
	parameterLength() int
	isGroupElement(n *big.Int) bool
	isFragmented(data []byte) bool
	parseFragmentPrefix(c *Conversation, data []byte) (rest []byte, ignore bool, ok bool)
	fragmentPrefix(n, total int, itags uint32, itagr uint32) []byte
	minFragmentSize() uint16
	whitespaceTag() []byte
	messageHeader(c *Conversation, msgType byte) ([]byte, error)
	parseMessageHeader(c *Conversation, msg []byte) ([]byte, []byte, error)
}

func newOtrVersion(v uint16, p policies) (version otrVersion, err error) {
	toCheck := policy(0)
	switch v {
	case 2:
		version = otrV2{}
		toCheck = allowV2
	case 3:
		version = otrV3{}
		toCheck = allowV3
	default:
		return nil, errUnsupportedOTRVersion
	}
	if !p.has(toCheck) {
		return nil, errInvalidVersion
	}
	return
}

func (c *Conversation) checkVersion(message []byte) (err error) {
	_, messageVersion, ok := extractShort(message)
	if !ok {
		return errInvalidOTRMessage
	}

	if c.version == nil {
		if c.version, err = newOtrVersion(messageVersion, c.Policies); err != nil {
			return err
		}
	}

	if c.version.protocolVersion() != messageVersion {
		return errWrongProtocolVersion
	}

	return nil
}
