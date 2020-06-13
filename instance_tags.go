package otr3

import "encoding/binary"

// GetOurInstanceTag returns our instance tag - it computes it if none has been computed yet
func (c *Conversation) GetOurInstanceTag() uint32 {
	_ = c.generateInstanceTag()
	return c.ourInstanceTag
}

// GetTheirInstanceTag returns the peers instance tag, or 0 if none has been computed yet
func (c *Conversation) GetTheirInstanceTag() uint32 {
	return c.theirInstanceTag
}

func (c *Conversation) generateInstanceTag() error {
	if c.ourInstanceTag != 0 {
		return nil
	}

	var ret uint32
	var dst [4]byte

	for ret < minValidInstanceTag {
		if err := c.randomInto(dst[:]); err != nil {
			return err
		}

		ret = binary.BigEndian.Uint32(dst[:])
	}

	c.ourInstanceTag = ret

	return nil
}
