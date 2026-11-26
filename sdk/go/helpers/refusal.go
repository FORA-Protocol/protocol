package helpers

import "errors"

// RefusalError reports why an operation refused, as a token of the shared reason
// vocabulary (sdk/parity/reasons.json in the protocol repository). Python and
// TypeScript report the same token for the same refusal, so a conformance corpus
// records it once and every SDK's replay compares it as it is.
//
// Err is the error the operation refused with. Error and Unwrap pass it through, so
// errors.Is against a sentinel such as ErrURLExpired, and the message, are what they
// were before the token was added.
type RefusalError struct {
	Reason string
	Err    error
}

func (e *RefusalError) Error() string { return e.Err.Error() }

func (e *RefusalError) Unwrap() error { return e.Err }

// RefusalReason returns the reason token.
func (e *RefusalError) RefusalReason() string { return e.Reason }

// refusal is an error that carries a reason token: a *RefusalError, or a typed
// refusal such as *PoPError that names its own token.
type refusal interface {
	error
	RefusalReason() string
}

// ReasonOf returns the reason token of the first refusal in err's chain, or "" when
// err is nil or carries none.
func ReasonOf(err error) string {
	var r refusal
	if errors.As(err, &r) {
		return r.RefusalReason()
	}
	return ""
}

// refusedFor wraps err as a refusal for reason.
func refusedFor(reason string, err error) error {
	return &RefusalError{Reason: reason, Err: err}
}
