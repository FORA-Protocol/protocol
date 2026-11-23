// Package wbadir holds the well-known path of a Web Bot Auth key directory and the
// one rule that turns a signer's configured origin into the Signature-Agent value
// it sends.
//
// draft-ietf-webbotauth-httpsig-protocol-01 makes every Signature-Agent member the
// URL of the key set itself, so a FORA signer sends
// https://<host>/.well-known/http-message-signatures-directory. Deployments
// configure the origin, and the helpers, the signing transport, the client's
// delivery proof and the key resolvers all need the same path and the same
// completion. One copy keeps them from drifting.
//
// Internal on purpose: the path is a protocol constant every SDK already exports
// under its own name, and the completion is a signer convenience, not a wire rule.
package wbadir

import "strings"

// Path is the well-known path a key directory is served at (RFC 8615, registered
// by the Web Bot Auth draft).
const Path = "/.well-known/http-message-signatures-directory"

// Complete returns the Signature-Agent value a signer configured with value
// sends. An https value with an empty path, no query and no fragment is an
// origin, and gets Path appended. Anything else is returned unchanged, so the
// helpers judge it as given and refuse a value that is not a key directory URL
// with their own typed error, rather than this function hiding it.
func Complete(value string) string {
	rest, ok := strings.CutPrefix(value, "https://")
	if !ok || rest == "" || strings.ContainsAny(rest, "/?#") {
		return value
	}
	return value + Path
}
