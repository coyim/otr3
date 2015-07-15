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
	version    otrVersion
	Rand       io.Reader
	smpState   smpState
	privateKey *PrivateKey
	akeContext
}

type akeContext struct {
	version             otrVersion
	Rand                io.Reader
	gx, gy, x, y        *big.Int
	gxBytes             []byte
	digest              [32]byte
	senderInstanceTag   uint32
	receiverInstanceTag uint32
}

func newContext(v otrVersion, rand io.Reader) *context {
	return &context{
		version: v,
		Rand:    rand,
		akeContext: akeContext{
			version: v,
			Rand:    rand,
		},
		smpState: smpStateExpect1{},
	}
}

type otrVersion interface {
	Int() uint16
	parameterLength() int
	isGroupElement(n *big.Int) bool
	isFragmented(data []byte) bool
	makeFragment(data []byte, n, total int, itags uint32, itagr uint32) []byte
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

var (
	dhCommitMsg = 0x02
	dhKeyMsg    = 0x0A
	dataMsg     = 0x03
)

// This should be used by the xmpp-client to received OTR messages in plain
//TODO toSend needs fragmentation to be implemented
func (c *context) receive(message []byte) (toSend []byte, err error) {

	if isQueryMessage(message) {
		toSend, err = c.receiveOTRQueryMessage(message)
		return
	}

	// TODO check the message instanceTag

	msgProtocolVersion := extractShort(message, 0)
	if c.version.Int() != msgProtocolVersion {
		return nil, errWrongProtocolVersion
	}

	msgType := int(message[2])

	switch msgType {
	case dhCommitMsg:
		toSend, err = c.receiveDHCommit(message)
	case dhKeyMsg:
		toSend, err = c.receiveDHKey(message)
	case dataMsg:
		//TODO: extract message from the encripted DATA
		//msg := decrypt(message)
		//err = c.receiveSMPMessage(msg)
	}

	return
}

func (c *context) receiveDHCommit(msg []byte) ([]byte, error) {
	ake := AKE{}
	ake.version = otrV3{}

	dataIndex := lenMsgHeader
	if ake.needInstanceTag() {
		receiverInstanceTag, _ := extractWord(msg, lenMsgHeader)
		c.senderInstanceTag = generateIntanceTag()
		c.receiverInstanceTag = receiverInstanceTag
		dataIndex = dataIndex + 8
	}
	dataIndex, c.gxBytes = extractData(msg, dataIndex)
	_, digest := extractData(msg, dataIndex)
	copy(c.digest[:], digest)

	ake.gxBytes = c.gxBytes
	ake.digest = c.digest
	ake.receiverInstanceTag = c.receiverInstanceTag
	ake.senderInstanceTag = c.senderInstanceTag

	return ake.dhKeyMessage()
}

func (c *context) receiveDHKey(msg []byte) ([]byte, error) {
	ake := AKE{
		akeContext: akeContext{
			x:       c.x,
			gx:      c.gx,
			version: c.version,
		},
		ourKey: c.privateKey,
	}

	gyPos := 3
	if ake.needInstanceTag() {
		gyPos = 11
	}

	_, ake.gy = extractMPI(msg, gyPos)

	return ake.revealSigMessage()
}
func generateIntanceTag() uint32 {
	//TODO generate this
	return 0x00000100 + 0x01
}

func (c *context) receiveOTRQueryMessage(message []byte) ([]byte, error) {
	if err := c.acceptOTRRequest(message); err != nil {
		return nil, err
	}

	ake := AKE{
		akeContext: akeContext{
			version:           c.version,
			Rand:              c.Rand,
			senderInstanceTag: generateIntanceTag(),
		},
	}

	ret, err := ake.dhCommitMessage()
	if err != nil {
		return ret, err
	}

	//TODO find a proper place for this
	c.x = ake.x
	c.gx = ake.gx
	c.senderInstanceTag = ake.senderInstanceTag

	return ret, nil
}

func (c *context) acceptOTRRequest(msg []byte) error {
	version := 0
	versions := parseOTRQueryMessage(msg)

	for _, v := range versions {
		if v > version {
			version = v
		}
	}

	switch version {
	case 2:
		c.version = otrV2{}
	case 3:
		c.version = otrV3{}
	default:
		return errUnsupportedOTRVersion
	}

	return nil
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

func (c *context) parameterLength() int {
	return c.version.parameterLength()
}

func (c *context) isGroupElement(n *big.Int) bool {
	return c.version.isGroupElement(n)
}

func (c *context) randMPI(buf []byte) *big.Int {
	io.ReadFull(c.rand(), buf)
	// TODO: errors here
	return new(big.Int).SetBytes(buf)
}
