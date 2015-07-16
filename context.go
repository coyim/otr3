package otr3

import (
	"bytes"
	"errors"
	"io"
	"math/big"
	"strconv"
)

const (
	lenMsgHeader = 3
)

var (
	errUnsupportedOTRVersion = errors.New("unsupported OTR version")
	errWrongProtocolVersion  = errors.New("wrong protocol version")
)

type context struct {
	otrContext
	smpState   smpState
	privateKey *PrivateKey
	akeContext
}

type akeContext struct {
	otrContext
	authState             authState
	gx, gy, x, y          *big.Int
	encryptedGx, hashedGx []byte
	digest                [32]byte
	senderInstanceTag     uint32
	receiverInstanceTag   uint32
}

type otrContext struct {
	otrVersion
	Rand io.Reader
}

func newContext(v otrVersion, rand io.Reader) *context {
	c := context{}
	c.otrContext = newOtrContext(v, rand)
	c.akeContext.otrContext = c.otrContext
	c.smpState = smpStateExpect1{}
	c.authState = authStateNone{}
	return &c
}

func newOtrContext(v otrVersion, rand io.Reader) otrContext {
	return otrContext{otrVersion: v, Rand: rand}
}

type otrVersion interface {
	protocolVersion() uint16
	parameterLength() int
	isGroupElement(n *big.Int) bool
	isFragmented(data []byte) bool
	makeFragment(data []byte, n, total int, itags uint32, itagr uint32) []byte
	needInstanceTag() bool
}

type conversation interface {
	send(message []byte)
	receive(message []byte) error
}

func (c *context) send(message []byte) {
	// FIXME Dummy for now
}

var queryMarker = []byte("?OTR")

func parseOTRQueryMessage(msg []byte) []int {
	ret := []int{}

	if bytes.HasPrefix(msg, queryMarker) {
		var p int
		versions := msg[len(queryMarker):]

		if versions[p] == '?' {
			ret = append(ret, 1)
			p++
		}

		if len(versions) > p && versions[p] == 'v' {
			for _, c := range versions[p:] {
				if v, err := strconv.Atoi(string(c)); err == nil {
					ret = append(ret, v)
				}
			}
		}
	}

	return ret
}

func isQueryMessage(msg []byte) bool {
	return bytes.HasPrefix(msg, []byte(queryMarker))
}

const (
	msgTypeDHCommit  = byte(2)
	msgData          = byte(3)
	msgTypeDHKey     = byte(10)
	msgTypeRevealSig = byte(17)
	msgTypeSig       = byte(18)
)

// This should be used by the xmpp-client to received OTR messages in plain
//TODO toSend needs fragmentation to be implemented
func (c *context) receive(message []byte) (toSend []byte, err error) {
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

func (c *context) receiveDHKey(msg []byte) ([]byte, error) {
	ake := AKE{}
	ake.otrVersion = c.otrVersion
	ake.akeContext = c.akeContext
	ake.ourKey = c.privateKey

	gyPos := 3
	if ake.needInstanceTag() {
		gyPos = 11
	}

	_, ake.gy = extractMPI(msg, gyPos)

	return ake.revealSigMessage()
}

func (c *context) receiveSMPMessage(message []byte) error {
	var err error
	m := parseTLV(message)
	c.smpState, err = m.receivedMessage(c.smpState)
	return err
}

func (c *context) rand() io.Reader {
	return c.Rand
}

func (c *context) randMPI(buf []byte) *big.Int {
	io.ReadFull(c.rand(), buf)
	// TODO: errors here
	return new(big.Int).SetBytes(buf)
}
