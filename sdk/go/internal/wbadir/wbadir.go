// Package wbadir holds the well-known path of a Web Bot Auth key directory.
//
// draft-ietf-webbotauth-httpsig-protocol-01 makes every Signature-Agent member the
// URL of the key set itself, so a FORA signer sends
// https://<host>/.well-known/http-message-signatures-directory and a FORA verifier
// reads that URL. The helpers, which write and read the member, and the key
// resolvers, which fetch the directory, need the same path. One copy keeps them
// from drifting.
//
// Internal on purpose: every SDK already exports the path under its own name
// (resolvers.WBADirectoryPath here), and the helpers tier may not import resolvers.
package wbadir

// Path is the well-known path a key directory is served at (RFC 8615, registered
// by the Web Bot Auth draft).
const Path = "/.well-known/http-message-signatures-directory"
