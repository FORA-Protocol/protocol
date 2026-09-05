"""Wire constants shared across the SDK — Python port of the sdk/go oracle
(helpers/constants.go + core/requestid.go). Encoding is negotiated per hop via
Content-Type (ADR-020): application/proto for binary, application/json for
canonical proto-JSON. The Go layer splits RequestIDHeader across
helpers/constants.go and core/requestid.go; the single Python module exposes all
of them once. Pinned to wire-constants-vectors.json.
"""

from __future__ import annotations

#: Content-Type for binary protobuf bodies.
ContentTypeProto = "application/proto"
#: Content-Type for canonical proto-JSON bodies.
ContentTypeJSON = "application/json"
#: Header carrying the Connect unary protocol version.
ConnectProtocolVersionHeader = "Connect-Protocol-Version"
#: The only Connect protocol version FORA speaks.
ConnectProtocolVersion = "1"
#: The FORA protocol version stamped on the ``ver`` field of every FORA message
#: — NOT the Connect transport version above. Senders stamp it from here so a
#: protocol bump is a single edit; receivers treat ``ver`` as advisory.
ProtocolVersion = "1.0"
#: Header correlating a request across services and the edge.
RequestIDHeader = "X-Request-ID"
#: Header carrying the signer's Web Bot Auth key-directory URL.
SignatureAgentHeader = "Signature-Agent"
#: Header carrying the fetcher's raw Ed25519 public key on a PoP GET. Canonical
#: (Go) casing; HTTP field names are case-insensitive, so lookups lowercase it —
#: see ``AGENT_KEY_HEADER`` in ``pop``, which derives from this rather than
#: restating the string.
AgentKeyHeader = "X-FORA-Agent-Key"
#: Path of the discovery document on every Exchange host. The one bootstrap
#: coordinate: a client holding only a hostname fetches
#: ``{scheme}://{host}{WellKnownPath}`` to learn the endpoint and the keys, so
#: the three SDKs agreeing on it is the precondition for interop, not a
#: tidiness concern.
WellKnownPath = "/.well-known/fora.json"
