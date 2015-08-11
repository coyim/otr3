package otr3

import "testing"

func Test_ErrorCode_hasValidStringImplementation(t *testing.T) {
	assertEquals(t, ErrorCodeEncryptionError.String(), "ErrorCodeEncryptionError")
	assertEquals(t, ErrorCodeMessageUnreadable.String(), "ErrorCodeMessageUnreadable")
	assertEquals(t, ErrorCodeMessageMalformed.String(), "ErrorCodeMessageMalformed")
	assertEquals(t, ErrorCode(20000).String(), "")
}
