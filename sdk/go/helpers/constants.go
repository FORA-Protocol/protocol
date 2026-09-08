package helpers

// Wire constants shared across the SDK. Encoding is negotiated per hop via
// Content-Type (ADR-020): application/proto for binary, application/json for
// canonical proto-JSON. connect-go serves both, so each leg picks independently.
const (
	// ContentTypeProto is the Content-Type for binary protobuf bodies.
	ContentTypeProto = "application/proto"
	// ContentTypeJSON is the Content-Type for canonical proto-JSON bodies.
	ContentTypeJSON = "application/json"
	// ConnectProtocolVersionHeader carries the Connect unary protocol version.
	ConnectProtocolVersionHeader = "Connect-Protocol-Version"
	// ConnectProtocolVersion is the only Connect protocol version FORA speaks.
	ConnectProtocolVersion = "1"
	// ProtocolVersion is the FORA protocol version stamped on the `ver` field of
	// every FORA message — NOT the Connect transport version above. It is the one
	// source this value comes from, so a protocol bump is a single edit here
	// rather than a literal hunt across every message builder. Senders MUST stamp
	// it; receivers treat `ver` as advisory — see "Protocol version" in fora.proto
	// for the receive-side rule, which is stated once, there. The
	// /.well-known/fora.json document carries its own document version in a
	// separate namespace, which this constant does NOT supply — that is
	// WellKnownManifestVersion below.
	ProtocolVersion = "1.0"
	// WellKnownManifestVersion is the version of the /.well-known/fora.json
	// DOCUMENT layout, stamped on WellKnownManifest.ver by every party that serves
	// one. It is a namespace separate from ProtocolVersion and is never derived
	// from it: a change to the manifest layout bumps both numbers, a protocol
	// change that leaves the manifest untouched bumps only ProtocolVersion. Both
	// read "1.0" today because neither has moved yet; neither is derived from
	// the other. The receive-side check a manifest reader applies is
	// CheckWellKnownManifestVersion.
	WellKnownManifestVersion = "1.0"
	// RequestIDHeader correlates a request across services and the edge.
	RequestIDHeader = "X-Request-ID"
	// SignatureAgentHeader carries the signer's Web Bot Auth key-directory URL
	// (the WBA identity anchor). It is a required covered component: every FORA
	// signature commits to it, empty included, so the directory a verifier
	// resolves keys from is the one the signer bound.
	SignatureAgentHeader = "Signature-Agent"
	// WellKnownPath is the discovery document's path on every Exchange host. It is
	// the one bootstrap coordinate in the protocol: a client that knows only a
	// hostname fetches {scheme}://{host}{WellKnownPath} to learn the endpoint and
	// the keys, so the three SDKs agreeing on it is not a tidiness concern but the
	// precondition for interop. It was built inline at each call site before, once
	// per language, which is exactly the shape that lets one port drift silently.
	// Named here so the wire-constants vectors can carry it and the Python and
	// TypeScript parity suites replay it against this value. WellKnownManifestVersion
	// above versions the document's CONTENT; this names WHERE it is served.
	WellKnownPath = "/.well-known/fora.json"
)

// signatureAgentLower is SignatureAgentHeader in the lowercase form RFC 9421
// covered-component names use.
const signatureAgentLower = "signature-agent"
