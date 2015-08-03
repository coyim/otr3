package otr3

import (
	"errors"
	"fmt"
)

var (
	// GPG_ERR_NO_ERROR is matched to nil
	// GPG_ERR_ENOMEM doesn't make any sense in golang

	// ErrGPGUnusableSecretKey maps to GPG_ERR_UNUSABLE_SECKEY in libotr
	ErrGPGUnusableSecretKey = errors.New("GPG Error: Unusable secret key (54)")
	// ErrGPGInvalidValue maps to GPG_ERR_INV_VALUE in libotr
	ErrGPGInvalidValue = errors.New("GPG Error: Invalid value (55)")
	// ErrGPGConflict maps to GPG_ERR_CONFLICT in libotr
	ErrGPGConflict = errors.New("GPG Error: Conflict (70)")
	// ErrGPGEntityExist maps to GPG_ERR_EEXIST in libotr
	ErrGPGEntityExist = errors.New("GPG Error: Entity exist (32803)")
)

var errCantAuthenticateWithoutEncryption = newOtrError("can't authenticate a peer without a secure conversation established")
var errCorruptEncryptedSignature = newOtrError("corrupt encrypted signature")
var errEncryptedMessageWithNoSecureChannel = newOtrError("encrypted message received without encrypted session established")
var errUnexpectedPlainMessage = newOtrError("plain message received when encryption was required")
var errInvalidOTRMessage = newOtrError("invalid OTR message")
var errInvalidVersion = newOtrError("no valid version agreement could be found") //libotr ignores this situation
var errNotWaitingForSMPSecret = newOtrError("not expected SMP secret to be provided now")
var errReceivedMessageForOtherInstance = newOtrError("received message for other OTR instance") //not exactly an error - we should ignore these messages by default
var errShortRandomRead = newOtrError("short read from random source")
var errUnexpectedMessage = newOtrError("unexpected SMP message")
var errUnsupportedOTRVersion = newOtrError("unsupported OTR version")
var errWrongProtocolVersion = newOtrError("wrong protocol version")

// OtrError is an error in the OTR library
type OtrError struct {
	msg string
}

func newOtrError(s string) error {
	return OtrError{s}
}

func newOtrErrorf(format string, a ...interface{}) error {
	return OtrError{fmt.Sprintf(format, a...)}
}

func (oe OtrError) Error() string {
	return "otr: " + oe.msg
}
