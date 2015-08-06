package otr3

import (
	"bytes"
	"strconv"
)

func isQueryMessage(msg ValidMessage) bool {
	return bytes.HasPrefix(msg, queryMarker)
}

func parseOTRQueryMessage(msg ValidMessage) []int {
	ret := []int{}

	if bytes.HasPrefix(msg, queryMarker) && len(msg) > len(queryMarker) {
		versions := msg[len(queryMarker):]

		if versions[0] == '?' {
			ret = append(ret, 1)
			versions = versions[1:]
		}

		if len(versions) > 0 && versions[0] == 'v' {
			for _, c := range versions {
				if v, err := strconv.Atoi(string(c)); err == nil {
					ret = append(ret, v)
				}
			}
		}
	}

	return ret
}

func acceptOTRRequest(p policies, msg ValidMessage) (otrVersion, bool) {
	versions := parseOTRQueryMessage(msg)

	for _, v := range versions {
		switch {
		case v == 3 && p.has(allowV3):
			return otrV3{}, true
		case v == 2 && p.has(allowV2):
			return otrV2{}, true
		}
	}

	return nil, false
}

func (c *Conversation) receiveQueryMessage(msg ValidMessage) ([]messageWithHeader, error) {
	v, ok := acceptOTRRequest(c.Policies, msg)
	if !ok {
		return nil, errInvalidVersion
	}
	c.version = v

	ts, err := c.sendDHCommit()
	return c.potentialAuthError(compactMessagesWithHeader(ts), err)
}

func (c Conversation) queryMessage() ValidMessage {
	queryMessage := []byte("?OTRv")

	if c.Policies.has(allowV2) {
		queryMessage = append(queryMessage, '2')
	}

	if c.Policies.has(allowV3) {
		queryMessage = append(queryMessage, '3')
	}

	return append(queryMessage, '?')
}
