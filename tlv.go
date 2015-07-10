package otr3

const tlvHeaderLength = 4

func parseTLV(data []byte) smpMessage {
	tlvType := extractShort(data, 0)
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

	return nil
}

func parseSMP1TLV(data []byte) *smpMessage1 {
	// TODO: errors
	var msg smpMessage1
	mpis := extractMPIs(data, tlvHeaderLength)
	msg.g2a = mpis[0]
	msg.c2 = mpis[1]
	msg.d2 = mpis[2]
	msg.g3a = mpis[3]
	msg.c3 = mpis[4]
	msg.d3 = mpis[5]
	return &msg
}

func parseSMP2TLV(data []byte) *smpMessage2 {
	// TODO: errors
	var msg smpMessage2
	mpis := extractMPIs(data, tlvHeaderLength)
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
	return &msg
}

func parseSMP3TLV(data []byte) *smpMessage3 {
	// TODO: errors
	var msg smpMessage3
	mpis := extractMPIs(data, tlvHeaderLength)
	msg.pa = mpis[0]
	msg.qa = mpis[1]
	msg.cp = mpis[2]
	msg.d5 = mpis[3]
	msg.d6 = mpis[4]
	msg.ra = mpis[5]
	msg.cr = mpis[6]
	msg.d7 = mpis[7]
	return &msg
}

func parseSMP4TLV(data []byte) *smpMessage4 {
	// TODO: errors
	var msg smpMessage4
	mpis := extractMPIs(data, tlvHeaderLength)
	msg.rb = mpis[0]
	msg.cr = mpis[1]
	msg.d7 = mpis[2]
	return &msg
}
