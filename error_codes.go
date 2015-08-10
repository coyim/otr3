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
