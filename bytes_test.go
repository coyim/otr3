package otr3

import "testing"

func Test_FragmentedMessage_canBeConvertedToSliceOfByteSlices(t *testing.T) {
	fragmented := FragmentedMessage{
		messageFragment{0x01, 0x02},
		messageFragment{0x03, 0x04},
		messageFragment{0x05, 0x06},
	}

	assertDeepEquals(t, fragmented.Bytes(), [][]byte{
		[]byte{0x01, 0x02},
		[]byte{0x03, 0x04},
		[]byte{0x05, 0x06},
	})
}
