package otr3

import "io"

type Conversation struct {
	version otrVersion
	Rand    io.Reader

	msgState msgState

	ourInstanceTag   uint32
	theirInstanceTag uint32

	ssid     [8]byte
	OurKey   *PrivateKey
	TheirKey *PublicKey

	ake      *ake
	smp      smp
	keys     keyManagementContext
	Policies policies

	fragmentSize              uint16
	stopSendingWhitespaceTags bool

	eventHandler *EventHandler
}

type msgState int

const (
	plainText msgState = iota
	encrypted
	finished
)

var (
	queryMarker = []byte("?OTR")
	errorMarker = []byte("?OTR Error:")
	msgMarker   = []byte("?OTR:")
)

func (c *Conversation) messageHeader(msgType byte) ([]byte, error) {
	return c.version.messageHeader(c, msgType)
}

func (c *Conversation) parseMessageHeader(msg []byte) ([]byte, []byte, error) {
	return c.version.parseMessageHeader(c, msg)
}

func (c *Conversation) wrapMessageHeader(msgType byte, msg []byte) ([]byte, error) {
	messageHeader, err := c.messageHeader(msgType)
	if err != nil {
		return nil, err
	}
	return append(messageHeader, msg...), nil
}

func (c *Conversation) IsEncrypted() bool {
	return c.msgState == encrypted
}

func (c *Conversation) End() (toSend [][]byte) {
	switch c.msgState {
	case plainText:
	case encrypted:
		c.msgState = plainText
		toSend = c.encode(c.genDataMsg(nil, tlv{tlvType: tlvTypeDisconnected}).serialize(c))
	case finished:
		c.msgState = plainText
	}
	return
}
