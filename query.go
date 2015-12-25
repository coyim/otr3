package otr3

import "bytes"

func isQueryMessage(msg ValidMessage) bool {
	return bytes.HasPrefix(msg, queryMarker)
}

func parseOTRQueryMessage(msg ValidMessage) []string {
	ret := []string{}

	if bytes.HasPrefix(msg, queryMarker) && len(msg) > len(queryMarker) {
		versions := msg[len(queryMarker):]

		if versions[0] == '?' {
			ret = append(ret, "1")
			versions = versions[1:]
		}

		if len(versions) > 0 && versions[0] == 'v' {
			for _, c := range versions[1:] {
				if c == '?' {
					break
				}
				ret = append(ret, string(c))
			}
		}
	}

	return ret
}

func extractVersionsFromQueryMessage(p policies, msg ValidMessage) map[string]bool {
	versions := make(map[string]bool)
	for _, v := range parseOTRQueryMessage(msg) {
		switch {
		case v == "J" && p.has(allowVExtensionJ):
			versions[v] = true
		case v == "3" && p.has(allowV3):
			versions[v] = true
		case v == "2" && p.has(allowV2):
			versions[v] = true
		}
	}

	return versions
}

func (c *Conversation) receiveQueryMessage(msg ValidMessage) ([]messageWithHeader, error) {
	versions := extractVersionsFromQueryMessage(c.Policies, msg)
	err := c.commitToVersionFrom(versions)
	if err != nil {
		return nil, err
	}

	ts, err := c.sendDHCommit()
	return c.potentialAuthError(compactMessagesWithHeader(ts), err)
}

//QueryMessage will return a QueryMessage determined by Conversation Policies
func (c Conversation) QueryMessage() ValidMessage {
	queryMessage := []byte("?OTRv")

	if c.Policies.has(allowV2) {
		queryMessage = append(queryMessage, '2')
	}

	if c.Policies.has(allowV3) {
		queryMessage = append(queryMessage, '3')
	}

	if c.Policies.has(allowVExtensionJ) {
		queryMessage = append(queryMessage, 'J')
	}

	return append(queryMessage, '?')
}
