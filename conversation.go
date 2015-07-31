package otr3

import "io"

type Conversation struct {
	version otrVersion
	Rand    io.Reader

	msgState msgState

	ourInstanceTag   uint32
	theirInstanceTag uint32

	ourKey   *PrivateKey
	theirKey *PublicKey

	keys keyManagementContext

	ssid         [8]byte
	policies     policies
	ake          *ake
	smp          smp
	fragmentSize uint16

	stopSendingWhitespaceTags bool
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

func (c *Conversation) messageHeader(msgType byte) []byte {
	return c.version.messageHeader(c, msgType)
}

func (c *Conversation) parseMessageHeader(msg []byte) ([]byte, error) {
	return c.version.parseMessageHeader(c, msg)
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
