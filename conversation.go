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

	ake       *ake
	smp       smp
	keys      keyManagementContext
	Policies  policies
	heartbeat heartbeatContext

	fragmentSize              uint16
	fragmentationContext      fragmentationContext
	stopSendingWhitespaceTags bool

	eventHandler EventHandler
	receiveChan  chan ValidMessage
	sendChan     chan ValidMessage
	toSendChan   chan ValidMessage
	plainChan    chan []byte
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

func (c *Conversation) parseMessageHeader(msg messageWithHeader) ([]byte, []byte, error) {
	return c.version.parseMessageHeader(c, msg)
}

func (c *Conversation) parseFragmentPrefix(data []byte) ([]byte, bool, bool) {
	return c.version.parseFragmentPrefix(c, data)
}

func (c *Conversation) wrapMessageHeader(msgType byte, msg []byte) (messageWithHeader, error) {
	header, err := c.messageHeader(msgType)
	if err != nil {
		return nil, err
	}

	return append(header, msg...), nil
}

func (c *Conversation) IsEncrypted() bool {
	return c.msgState == encrypted
}

func (c *Conversation) End() (toSend []ValidMessage, err error) {
	switch c.msgState {
	case plainText:
	case encrypted:
		//NOTE:Error can only happen when Rand reader is broken
		toSend, err = c.createSerializedDataMessage(nil, messageFlagIgnoreUnreadable, []tlv{tlv{tlvType: tlvTypeDisconnected}})
	case finished:
	}
	c.msgState = plainText
	c.keys.ourCurrentDHKeys.wipe()
	c.keys.ourPreviousDHKeys.wipe()
	wipeBigInt(c.keys.theirCurrentDHPubKey)
	return
}
