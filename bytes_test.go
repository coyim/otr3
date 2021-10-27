package otr3

import "testing"

func Test_FragmentedMessage_canBeConvertedToSliceOfByteSlices(t *testing.T) {
	fragmented := []ValidMessage{
		{0x01, 0x02},
		{0x03, 0x04},
		{0x05, 0x06},
	}

	assertDeepEquals(t, Bytes(fragmented), [][]byte{
		{0x01, 0x02},
		{0x03, 0x04},
		{0x05, 0x06},
	})
}
