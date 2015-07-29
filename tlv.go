package otr3

const tlvHeaderLength = 4

const (
	tlvTypePadding      = 0
	tlvTypeDisconnected = 1
	tlvTypeSMP1         = 2
	tlvTypeSMP2         = 3
	tlvTypeSMP3         = 4
	tlvTypeSMP4         = 5
	tlvTypeSMPAbort     = 6
	//TODO: Question is not done
	tlvTypeSMP1WithQuestion = 7
)

type tlv struct {
	tlvType   uint16
	tlvLength uint16
	tlvValue  []byte
}

func (c tlv) serialize() []byte {
	out := appendShort([]byte{}, c.tlvType)
	out = appendShort(out, c.tlvLength)
	return append(out, c.tlvValue...)
}

func (c *tlv) deserialize(tlvsBytes []byte) error {
	var ok bool
	tlvsBytes, c.tlvType, ok = extractShort(tlvsBytes)
	if !ok {
		return newOtrError("wrong tlv type")
	}
	tlvsBytes, c.tlvLength, ok = extractShort(tlvsBytes)
	if !ok {
		return newOtrError("wrong tlv length")
	}
	if len(tlvsBytes) < int(c.tlvLength) {
		return newOtrError("wrong tlv value")
	}
	c.tlvValue = tlvsBytes[:int(c.tlvLength)]
	return nil
}

func parseTLV(data []byte) (smpMessage, bool) {
	_, tlvType, ok := extractShort(data)
	if !ok {
		return nil, false
	}
	switch tlvType {
	case 0x02:
		return parseSMP1TLV(data)
	case 0x03:
		return parseSMP2TLV(data)
	case 0x04:
		return parseSMP3TLV(data)
	case 0x05:
		return parseSMP4TLV(data)
	}

	return nil, false
}

func parseSMP1TLV(data []byte) (msg smp1Message, ok bool) {
	_, mpis, ok := extractMPIs(data[tlvHeaderLength:])
	if !ok || len(mpis) < 6 {
		return msg, false
	}
	msg.g2a = mpis[0]
	msg.c2 = mpis[1]
	msg.d2 = mpis[2]
	msg.g3a = mpis[3]
	msg.c3 = mpis[4]
	msg.d3 = mpis[5]
	return msg, true
}

func parseSMP2TLV(data []byte) (msg smp2Message, ok bool) {
	_, mpis, ok := extractMPIs(data[tlvHeaderLength:])
	if !ok || len(mpis) < 11 {
		return msg, false
	}
	msg.g2b = mpis[0]
	msg.c2 = mpis[1]
	msg.d2 = mpis[2]
	msg.g3b = mpis[3]
	msg.c3 = mpis[4]
	msg.d3 = mpis[5]
	msg.pb = mpis[6]
	msg.qb = mpis[7]
	msg.cp = mpis[8]
	msg.d5 = mpis[9]
	msg.d6 = mpis[10]
	return msg, true
}

func parseSMP3TLV(data []byte) (msg smp3Message, ok bool) {
	_, mpis, ok := extractMPIs(data[tlvHeaderLength:])
	if !ok || len(mpis) < 8 {
		return msg, false
	}
	msg.pa = mpis[0]
	msg.qa = mpis[1]
	msg.cp = mpis[2]
	msg.d5 = mpis[3]
	msg.d6 = mpis[4]
	msg.ra = mpis[5]
	msg.cr = mpis[6]
	msg.d7 = mpis[7]
	return msg, true
}

func parseSMP4TLV(data []byte) (msg smp4Message, ok bool) {
	_, mpis, ok := extractMPIs(data[tlvHeaderLength:])
	if !ok || len(mpis) < 3 {
		return msg, false
	}
	msg.rb = mpis[0]
	msg.cr = mpis[1]
	msg.d7 = mpis[2]
	return msg, true
}
