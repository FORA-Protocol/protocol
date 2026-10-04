package connectserver

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"

	connectrpc "connectrpc.com/connect"
	"google.golang.org/protobuf/encoding/protojson"

	forav1 "github.com/FORA-Protocol/protocol/gen/go/fora/v1"
	"github.com/FORA-Protocol/protocol/sdk/go/helpers"
)

// RejectCode maps a verify-face rejection sentinel to the Connect code returned to
// the client. Two rejections are resource/policy limits rather than authentication
// failures and say so: a hop-budget rejection (ErrTooManyHops), and a body past the
// read cap, which the buffering read reports as *http.MaxBytesError. Every other
// rejection (bad signature, replay, broken chain, expiry, missing headers) is an
// authentication failure. Classifying an over-size body as Unauthenticated would
// tell a correctly-signed caller its credentials were wrong, and would hide the one
// refusal a caller fixes by sending less. It is a pure, stateless error→code
// mapping — the budget and cap VALUES stay injected.
//
// It answers the TRANSPORT question; ClassifyReject answers the AUDIT question over
// the same errors. The two do not agree on every input, and the doc on ClassifyReject
// says where: RejectReason has no value for a body past the read cap.
//
// It is exported so a mount whose gate carries its OWN resource-limit sentinel — one
// this package cannot know about — answers that case itself and defers every other
// case here, instead of re-deriving the whole mapping. That is the composition
// WriteReject is shaped for.
func RejectCode(err error) connectrpc.Code {
	if errors.Is(err, helpers.ErrTooManyHops) || IsBodyTooLarge(err) {
		return connectrpc.CodeResourceExhausted
	}
	return connectrpc.CodeUnauthenticated
}

// IsBodyTooLarge reports whether err is net/http's over-cap signal from the read the
// body bound wraps — the error http.MaxBytesHandler / http.MaxBytesReader produces
// once a body passes the cap.
//
// It is exported because the classification has callers outside the response path: a
// middleware that must decide, before it can answer, whether the read it just failed
// was a size refusal or a malformed request. Only the size refusal is this package's
// to answer — WriteReject writes it; a malformed read is the caller's own verdict and
// its own response. What must not fork is the predicate the branch turns on, which is
// why it lives here rather than in a copy.
func IsBodyTooLarge(err error) bool {
	var maxBytes *http.MaxBytesError
	return errors.As(err, &maxBytes)
}

// httpStatus maps a rejection to its canonical Connect-over-HTTP status. The two
// ResourceExhausted causes separate here because they ask the caller for different
// things: a body past the cap is 413 (send less), a hop budget is 429 (send fewer,
// or slower). Unauthenticated is 401, and so is every other code — the domain this
// writer accepts is stated on WriteReject.
//
// The 413 is a deliberate departure from the Connect specification, which maps
// ResourceExhausted to 429 for every cause. That is exactly why the split lives in
// one place: it is not the canonical answer, so a second implementation derives the
// canonical one and the two mounts disagree. The over-cap arm is gated on the code
// as well as the error so a caller that classifies a rejection as something other
// than a resource limit cannot be answered 413 over a body that says otherwise.
//
// It stays unexported: nothing needs the status without also wanting the body that
// goes with it, and WriteReject is that pairing.
func httpStatus(code connectrpc.Code, err error) int {
	switch {
	case code == connectrpc.CodeResourceExhausted && IsBodyTooLarge(err):
		return http.StatusRequestEntityTooLarge
	case code == connectrpc.CodeResourceExhausted:
		return http.StatusTooManyRequests
	default:
		return http.StatusUnauthorized
	}
}

// WriteReject emits a Connect-compatible error response so a Connect client sees a
// proper code (and matching HTTP status) instead of a raw status. The body shape
// is Connect's unary error JSON: code and message, where err's own text is the
// message, so a caller that rejects with a wrapped internal error publishes that
// text.
//
// An Unauthenticated refusal also carries one fora.v1.ErrorDetail in details,
// whose request_auth_failure block holds the typed reason requestAuthFailureReason
// derives from err, because the contract tells a client to branch on a typed reason
// and never on the message. The detail's message is err's text, the same as the
// envelope's, and its domain is empty: this writer is handed no request, so it
// cannot name the service the refused call was addressed to, and the reason block
// already says which surface refused. No other code carries a detail: a resource
// limit has no reason block in the contract, and a code outside the two this writer
// models is the caller's verdict, not a signature refusal.
//
// The code is a parameter rather than derived, so a mount whose gate carries a
// resource-limit sentinel this package cannot know about supplies its own verdict
// and still gets this status split and this body. A caller with no such sentinel
// passes RejectCode(err), which is what this package's own handlers do.
//
// It answers the verify seam's two verdicts. ResourceExhausted is a resource or
// policy limit — 413 for a body past the read cap, 429 otherwise; Unauthenticated is
// 401, and carries an Accept-Signature header naming the components and form the
// profile requires when the request was unsigned, a signature omits a required
// component, or its tag or Signature-Agent form is refused
// (helpers.AcceptSignatureFor). Any other Connect code is answered 401 as well, and the body still reports the
// code the caller passed: this is a REJECTION writer, not a code→status table, and it
// refuses rather than translating a verdict it does not model. connect-go keeps the
// canonical table unexported, so a copy of it here would be the second authority this
// function exists to remove; a caller holding a verdict outside those two — a
// malformed request, say — writes that response itself.
func WriteReject(w http.ResponseWriter, code connectrpc.Code, err error) {
	ce := connectrpc.NewError(code, err)
	out := rejectBody{Code: code.String(), Message: ce.Message()}
	if code == connectrpc.CodeUnauthenticated {
		detail := helpers.RequestAuthFailureDetail("", ce.Message(), requestAuthFailureReason(err))
		if wd, ok := wireDetailOf(detail); ok {
			out.Details = []wireDetail{wd}
		}
	}
	w.Header().Set("Content-Type", "application/json")
	if code == connectrpc.CodeUnauthenticated {
		// WG-00 §5.3: a refusal for a missing component or a form the profile does
		// not accept names what the verifier requires, so a Web Bot Auth library
		// can add the components and sign again.
		if accept, ok := helpers.AcceptSignatureFor(err); ok {
			w.Header().Set(helpers.AcceptSignatureHeader, accept)
		}
	}
	w.WriteHeader(httpStatus(code, err))
	body, _ := json.Marshal(out)
	_, _ = w.Write(body)
}

// rejectBody is Connect's unary error JSON. message is always written, as it was
// before details existed, so a refusal without a detail keeps its exact bytes.
type rejectBody struct {
	Code    string       `json:"code"`
	Message string       `json:"message"`
	Details []wireDetail `json:"details,omitempty"`
}

// wireDetail is one entry of a Connect error's details array, in the form connect-go
// itself writes and reads: the message's fully qualified name, its binary protobuf as
// unpadded standard base64, and a debug rendering at protojson's default options. A
// Go client decodes value; the JSON-only SDKs have no binary codec and read debug,
// which is lowerCamelCase for exactly that reason. connect-go keeps its own encoder
// unexported, so the shape is restated here and a test holds it equal to what
// connect-go's ErrorWriter emits for the same error.
type wireDetail struct {
	Type  string          `json:"type"`
	Value string          `json:"value"`
	Debug json.RawMessage `json:"debug,omitempty"`
}

// wireDetailOf renders d as a details entry. It reports false when d cannot be
// marshalled, and the refusal is then written without a detail rather than not at
// all, the same best-effort rule AttachDetail follows.
func wireDetailOf(d *forav1.ErrorDetail) (wireDetail, bool) {
	cd, err := connectrpc.NewErrorDetail(d)
	if err != nil {
		return wireDetail{}, false
	}
	out := wireDetail{Type: cd.Type(), Value: base64.RawStdEncoding.EncodeToString(cd.Bytes())}
	if debug, derr := (protojson.MarshalOptions{}).Marshal(d); derr == nil {
		out.Debug = debug
	}
	return out, true
}

// requestAuthFailureReason maps a verify-face rejection to the typed reason an
// Unauthenticated refusal carries. The three reasons name what the caller does next,
// never which check failed, so several sentinels share each one:
//
//   - SIGNATURE_MISSING: no Signature-Input or Signature header, or one that does not
//     parse. The caller signs the request.
//   - SIGNATURE_STALE: expired, created in the future, or a nonce the replay store has
//     already seen. The caller signs the request again, now.
//   - SIGNATURE_INVALID: everything else, including an error this function has never
//     heard of. The default is the arm that matters: a sentinel added to the verifier
//     later lands here without an edit, and the most general reason is the only one
//     that cannot send a caller after the wrong remedy.
func requestAuthFailureReason(err error) forav1.RequestAuthFailureReason {
	switch {
	case errors.Is(err, helpers.ErrMissingSignatureInput),
		errors.Is(err, helpers.ErrMissingSignature),
		errors.Is(err, helpers.ErrMalformedSignatureInput):
		return forav1.RequestAuthFailureReason_REQUEST_AUTH_FAILURE_REASON_SIGNATURE_MISSING
	case errors.Is(err, helpers.ErrExpired),
		errors.Is(err, helpers.ErrFutureCreated),
		errors.Is(err, ErrReplayed):
		return forav1.RequestAuthFailureReason_REQUEST_AUTH_FAILURE_REASON_SIGNATURE_STALE
	default:
		return forav1.RequestAuthFailureReason_REQUEST_AUTH_FAILURE_REASON_SIGNATURE_INVALID
	}
}

// AsConnectError builds a *connect.Error of the given Code with detail attached
// as a typed error detail (the ADR-019 transport mechanism). The detail's
// Message becomes the error string. It lives in the SERVER binding (the emit
// direction: a server EMITS a typed error detail) — not the transport-neutral L1
// helpers — so a non-Connect consumer of helpers/core compiles zero connectrpc; the
// neutral *forav1.ErrorDetail builders and Reason stay in helpers, and this is where
// the ErrorDetail meets the Connect transport. The read direction (ErrorDetailFrom)
// lives in the client binding sdk/go/connect.
func AsConnectError(code connectrpc.Code, detail *forav1.ErrorDetail) *connectrpc.Error {
	msg := "fora error"
	if detail.GetMessage() != "" {
		msg = detail.GetMessage()
	}
	cerr := connectrpc.NewError(code, errors.New(msg))
	if d, err := connectrpc.NewErrorDetail(detail); err == nil {
		cerr.AddDetail(d)
	}
	return cerr
}
