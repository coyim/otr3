package otr3

// ErrorCode represents an error that can happen during OTR processing
type ErrorCode int

const (
	// ErrorCodeEncryptionError means an error occured while encrypting a message
	ErrorCodeEncryptionError ErrorCode = iota

	// ErrorCodeMessageUnreadable means we received an unreadable encrypted message
	ErrorCodeMessageUnreadable

	// ErrorCodeMessageMalformed means the message sent is malformed
	ErrorCodeMessageMalformed
)

func (s ErrorCode) String() string {
	switch s {
	case ErrorCodeEncryptionError:
		return "ErrorCodeEncryptionError"
	case ErrorCodeMessageUnreadable:
		return "ErrorCodeMessageUnreadable"
	case ErrorCodeMessageMalformed:
		return "ErrorCodeMessageMalformed"
	default:
		return "ERROR CODE: (THIS SHOULD NEVER HAPPEN)"
	}
}
