package helpers

import (
	"crypto/ed25519"
	"errors"
	"net/http"
	"testing"
	"time"
)

// WG-00 Appendix E.2: the draft's own Ed25519 test vectors, over the RFC 9421
// Appendix B.1.4 key. They cover only @authority and the Signature-Agent member,
// which a FORA RPC refuses for want of its four components — "where the profile
// allows" admits none of them at an RPC. What they do pin is that this SDK rebuilds
// the draft's signature base byte for byte, the dictionary-member serialization
// included, so a signature from a WG-00 library verifies here once it covers
// FORA's components.
func TestWG00AppendixE2_signatureBasesVerify(t *testing.T) {
	seed := mustHex("9f8362f87a484a954e6e740c5b4c0e84229139a20aa8ab56ff66586f6a7d29c5")
	pub := ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)
	for _, tc := range []struct {
		name, agent, input, sig string
	}{
		{
			name:  "E.2.1 dictionary member",
			agent: `agent2="https://signature-agent.test"`,
			input: `sig2=("@authority" "signature-agent";key="agent2");created=1735689600;keyid="poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U";alg="ed25519";expires=4889289600;nonce="n9p433xm+NJ3ph3upfBIGmsuwHw387YV7Q/F+6BSpGCVjYCqQw6rznNA8PVVLySrAWsv0hQtFioQb6E1YsauiA==";tag="web-bot-auth"`,
			sig:   "sig2=:RdNFx5Bj6au3YgAMQL/RzmUlZE8QZLIaXGRpw985hWnwPfMxT228NMk6ehRS1PSl4e8PhbNZACSanGdhEwYCCg==:",
		},
		{
			name:  "E.2.2 legacy String",
			agent: `"https://signature-agent.test"`,
			input: `sig2=("@authority" "signature-agent");created=1735689600;keyid="poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U";alg="ed25519";expires=1735693200;nonce="e8N7S2MFd/qrd6T2R3tdfAuuANngKI7LFtKYI/vowzk4lAZYadIX6wW25MwG7DCT9RUKAJ0qVkU0mEeLElW1qg==";tag="web-bot-auth"`,
			sig:   "sig2=:jdq0SqOwHdyHr9+r5jw3iYZH6aNGKijYp/EstF4RQTQdi5N5YYKrD+mCT1HA1nZDsi6nJKuHxUi/5Syp3rLWBA==:",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req, err := http.NewRequest(http.MethodPost, "https://example.com/foo?param=Value&Pet=dog", nil)
			if err != nil {
				t.Fatal(err)
			}
			req.Header.Set(SignatureAgentHeader, tc.agent)
			req.Header.Set("Signature-Input", tc.input)
			req.Header.Set("Signature", tc.sig)
			all, sigs, err := parseAllSignatures(req.Header)
			if err != nil {
				t.Fatal(err)
			}
			base, err := buildSignatureBase(req, all[0])
			if err != nil {
				t.Fatal(err)
			}
			if !ed25519.Verify(pub, []byte(base), sigs["sig2"]) {
				t.Fatalf("the draft's signature does not verify over the rebuilt base:\n%s", base)
			}
			dir, err := signatureDirectory(req.Header, all[0], 1)
			if err != nil || dir != "https://signature-agent.test" {
				t.Fatalf("directory = %q, %v", dir, err)
			}
			_, err = VerifyRequest(req, nil, pub, VerifyOptions{Now: time.Unix(1735689700, 0)})
			var missing *MissingComponentError
			if !errors.As(err, &missing) || missing.Component != "@method" {
				t.Fatalf("a FORA RPC verifier answered %v, want the missing @method", err)
			}
		})
	}
}

// TestWG00AppendixE23_directoryResponseVerifiesWithoutAlg: the draft's own signed
// directory response carries no alg, and a FORA verifier accepts its signature,
// because the key, which is Ed25519, decides the algorithm. Its key carries no
// not_before or not_after, so a FORA resolver still would not hand it out; this
// pins the response signature only.
func TestWG00AppendixE23_directoryResponseVerifiesWithoutAlg(t *testing.T) {
	pub := ed25519.NewKeyFromSeed(rfc9421Seed).Public().(ed25519.PublicKey)
	body := []byte(`{"keys":[{"kty":"OKP","crv":"Ed25519","kid":"poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U","x":"JrQLj5P_89iXES9-vFgrIy29clF9CC_oPPsw3c5D0bs","use":"sig"}]}`)
	h := http.Header{}
	h.Set("Content-Digest", "sha-256=:CADMT2aBdV/rqQr/NIru64ERQkCobVvllA4V0fLFDu0=:")
	h.Set("Signature-Input", `binding=("@authority";req "content-digest");created=1735689600;expires=4889289600;keyid="poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U";tag="http-message-signatures-directory"`)
	h.Set("Signature", "binding=:l6P8R67tm3kujAxbHWio7ll01qrEZ0dKD/WWlGhNYEmTnFZM8Wt0VQ9zqGfvo7T/UMkBxsigzChM1Gpz7gOVBg==:")
	got, err := VerifyDirectoryResponse("signature-agent.test", h, body, []ed25519.PublicKey{pub}, time.Unix(1735689700, 0))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || !got["poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U"] {
		t.Fatalf("verified %v, want the draft's one key", got)
	}
}

// TestAlgAccepted_readsPresence: the parser records whether a signature carries
// alg at all, so an absent alg is accepted and an empty one is refused. A sigParams
// built by hand reads as alg present, so it is judged by its Alg alone.
func TestAlgAccepted_readsPresence(t *testing.T) {
	for _, tc := range []struct {
		name, params string
		want         bool
	}{
		{"absent", ``, true},
		{"ed25519", `;alg="ed25519"`, true},
		{"ed25519 in upper case", `;alg="ED25519"`, true},
		{"empty", `;alg=""`, false},
		{"another algorithm", `;alg="rsa-pss-sha512"`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := http.Header{}
			h.Set("Signature-Input", `sig1=("@method");keyid="k"`+tc.params)
			h.Set("Signature", "sig1=:AAAA:")
			all, _, err := parseAllSignatures(h)
			if err != nil {
				t.Fatal(err)
			}
			if got := all[0].algAccepted(); got != tc.want {
				t.Errorf("algAccepted() = %v, want %v", got, tc.want)
			}
		})
	}
	if (sigParams{}).algAccepted() {
		t.Error("a hand-built sigParams with an empty Alg was accepted")
	}
}
