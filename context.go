package otr3

import (
	"bytes"
	"errors"
	"io"
	"math/big"
)

const (
	lenMsgHeader = 3
)

var (
	errUnsupportedOTRVersion = errors.New("unsupported OTR version")
	errWrongProtocolVersion  = errors.New("wrong protocol version")
)

type conversation struct {
	*otrContext
	smpState smpState
	akeContext
}

type akeContext struct {
	*otrContext
	authState             authState
	gx, gy, x, y          *big.Int
	encryptedGx, hashedGx []byte
	digest                [32]byte
	senderInstanceTag     uint32
	receiverInstanceTag   uint32
	ourKey                *PrivateKey
	theirKey              *PublicKey
	policies
}

type otrContext struct {
	otrVersion // TODO: this is extremely brittle and can cause unexpected interactions. We should revisit the decision to embed here
	Rand       io.Reader
}

func newConversation(v otrVersion, rand io.Reader) *conversation {
	c := newOtrContext(v, rand)
	return &conversation{
		otrContext: c,
		akeContext: akeContext{
			otrContext: c,
			authState:  authStateNone{},
			policies:   policies{},
		},
		smpState: smpStateExpect1{},
	}
}

func newOtrContext(v otrVersion, rand io.Reader) *otrContext {
	return &otrContext{otrVersion: v, Rand: rand}
}

type otrVersion interface {
	protocolVersion() uint16
	parameterLength() int
	isGroupElement(n *big.Int) bool
	isFragmented(data []byte) bool
	fragmentPrefix(n, total int, itags uint32, itagr uint32) []byte
	needInstanceTag() bool
}

func (c *akeContext) newAKE() AKE {
	return AKE{
		akeContext: *c,
	}
}

func (c *conversation) send(message []byte) {
	// FIXME Dummy for now
}

var queryMarker = []byte("?OTR")

func isQueryMessage(msg []byte) bool {
	return bytes.HasPrefix(msg, []byte(queryMarker))
}

// This should be used by the xmpp-client to received OTR messages in plain
//TODO toSend needs fragmentation to be implemented
func (c *conversation) receive(message []byte) (toSend []byte, err error) {
	if isQueryMessage(message) {
		toSend = c.akeContext.receiveQueryMessage(message)
		return
	}

	// TODO check the message instanceTag for V3
	// I should ignore the message if it is not for my conversation

	msgProtocolVersion := extractShort(message, 0)
	if c.protocolVersion() != msgProtocolVersion {
		return nil, errWrongProtocolVersion
	}

	msgType := message[2]

	switch msgType {
	case msgData:
		//TODO: extract message from the encripted DATA
		//msg := decrypt(message)
		//err = c.receiveSMPMessage(msg)
	default:
		toSend = c.akeContext.receiveMessage(message)
	}

	return
}

//NOTE: this is a candidate for an smpContext that would manage the smp state machine
// (just like the akeContext)
func (c *conversation) receiveSMPMessage(message []byte) error {
	var err error
	m := parseTLV(message)
	c.smpState, err = m.receivedMessage(c.smpState)
	return err
}

func (c *otrContext) rand() io.Reader {
	//WHY?
	return c.Rand
}

func (c *otrContext) randMPI(buf []byte) *big.Int {
	io.ReadFull(c.rand(), buf)
	// TODO: errors here
	return new(big.Int).SetBytes(buf)
}
