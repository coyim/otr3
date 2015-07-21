package otr3

import (
	"bytes"
	"crypto/sha256"
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
	smpContext
	akeContext
}

type smpContext struct {
	*otrContext
	smpState
	secret *big.Int
	s1     smp1
	s2     smp2
	s3     smp3
}

type akeContext struct {
	*otrContext
	authState           authState
	r                   [16]byte
	gx, gy, x, y        *big.Int
	encryptedGx         []byte
	hashedGx            [sha256.Size]byte
	sigKey              akeKeys
	senderInstanceTag   uint32
	receiverInstanceTag uint32
	ourKey              *PrivateKey
	theirKey            *PublicKey
	revealSigMsg        []byte
	policies
}

type otrContext struct {
	otrVersion // TODO: this is extremely brittle and can cause unexpected interactions. We should revisit the decision to embed here
	Rand       io.Reader
}

func newSmpContext(v otrVersion, r io.Reader) *smpContext {
	c := newOtrContext(v, r)
	return &smpContext{
		otrContext: c,
		smpState:   smpStateExpect1{},
	}
}

func newConversation(v otrVersion, rand io.Reader) *conversation {
	c := newOtrContext(v, rand)
	return &conversation{
		otrContext: c,
		akeContext: akeContext{
			otrContext: c,
			authState:  authStateNone{},
			policies:   policies(0),
		},
		smpContext: smpContext{
			otrContext: c,
			smpState:   smpStateExpect1{},
		},
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
	headerLen() int
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
	// TODO: errors?
	if isQueryMessage(message) {
		toSend = c.akeContext.receiveQueryMessage(message)
		return
	}

	// TODO check the message instanceTag for V3
	// I should ignore the message if it is not for my conversation

	_, msgProtocolVersion, _ := extractShort(message)
	if c.protocolVersion() != msgProtocolVersion {
		return nil, errWrongProtocolVersion
	}

	msgType := message[2]

	switch msgType {
	case msgData:
		//TODO: extract message from the encripted DATA
		//msg := decrypt(message)
		c.smpContext.receive(message)
	default:
		toSend, _ = c.akeContext.receiveMessage(message)
	}

	return
}

func (c *otrContext) rand() io.Reader {
	if c.Rand != nil {
		return c.Rand
	}
	return c.Rand
}

func (c *otrContext) randMPI(buf []byte) (*big.Int, bool) {
	_, err := io.ReadFull(c.rand(), buf)

	if err != nil {
		return nil, false
	}

	return new(big.Int).SetBytes(buf), true
}
