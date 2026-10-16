package connect_test

// ErrorDetail binary-decoding cross-language golden-vector emitter.
//
// A Connect error carries its typed reason as `details[].value`: the binary protobuf
// encoding of fora.v1.ErrorDetail, base64-encoded. Go opens it with the generated
// code. The Python and TypeScript SDKs have no protobuf runtime, so each carries a small
// table-driven decoder for the ErrorDetail subtree — the ErrorDetail message, its eight
// reason messages, RegistrationFieldError, and the enums they use. A decoder table is a
// second statement of the shape, so this corpus pins it from both sides:
//
//   - `wire` is the subtree's field and enum tables, read from the compiled descriptor.
//     Each JSON SDK asserts its own table is EQUAL to it, so a field added to the proto
//     fails their suites until their table carries it.
//   - `vectors` are binary encodings and the canonical proto-JSON each must decode to.
//     Between them every field of every message in the subtree is set at least once
//     (checked below against the same descriptor), alongside the encodings a decoder
//     must accept without the generated code to lean on: an unpacked repeated enum, a
//     singular field written twice (the last value wins), unknown fields of every wire
//     type, and the empty message.
//
// Values are marshaled with Deterministic set, so a map with two entries encodes the
// same bytes on every run and the drift gate fires only on a real change.
//
// Like the other emitters this test is a verification no-op by default (it asserts the
// committed file matches a fresh emit) and (re)writes it under FORA_UPDATE_VECTORS=1.
// It is TEST INFRASTRUCTURE, not the code under test.

import (
	"encoding/base64"
	"os"
	"reflect"
	"sort"
	"strconv"
	"testing"

	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"

	forav1 "github.com/FORA-Protocol/protocol/gen/go/fora/v1"
	"github.com/FORA-Protocol/protocol/sdk/go/internal/vectorio"
)

const errorDetailWireVectorsPath = "testdata/error-detail-wire-vectors.json"

// wireField is one field of a message in the decoder table.
type wireField struct {
	Name   string `json:"name"`
	Number int    `json:"number"`
	// Kind is the protobuf kind ("string", "enum", "message", ...), or "map".
	Kind string `json:"kind"`
	// Type is the fully-qualified enum or message name for those kinds, "" otherwise.
	Type     string `json:"type,omitempty"`
	Repeated bool   `json:"repeated,omitempty"`
	// MapKey and MapValue are the key and value kinds of a map field.
	MapKey   string `json:"map_key,omitempty"`
	MapValue string `json:"map_value,omitempty"`
}

// wireVector is one binary ErrorDetail and the proto-JSON it decodes to.
type wireVector struct {
	Name string `json:"name"`
	// Value is the binary encoding, base64 with the standard alphabet and no padding,
	// which is how connect-go writes details[].value.
	Value string `json:"value"`
	// Detail is the canonical proto-JSON under the proto field names.
	Detail any `json:"detail"`
}

// TestGenerateErrorDetailWireVectors emits the ErrorDetail binary-decoding corpus.
func TestGenerateErrorDetailWireVectors(t *testing.T) {
	messages, enums := errorDetailWireTables()
	vectors := buildErrorDetailWireVectors(t)
	requireEveryFieldSet(t, vectors)
	doc := map[string]any{
		"note": "Binary fora.v1.ErrorDetail encodings and their canonical proto-JSON, for the " +
			"table-driven decoders of the JSON SDKs. wire.messages and wire.enums are the " +
			"ErrorDetail subtree read from the compiled descriptor; every field of every " +
			"message there is set in at least one vector.",
		"wire":    map[string]any{"messages": messages, "enums": enums},
		"vectors": vectors,
	}
	if os.Getenv("FORA_UPDATE_VECTORS") == "1" {
		if err := vectorio.Write(errorDetailWireVectorsPath, doc); err != nil {
			t.Fatalf("write %s: %v", errorDetailWireVectorsPath, err)
		}
		return
	}
	stale, err := vectorio.Stale(errorDetailWireVectorsPath, doc)
	if err != nil {
		t.Fatalf("read %s: %v", errorDetailWireVectorsPath, err)
	}
	if stale {
		t.Fatalf("%s is stale; re-run with FORA_UPDATE_VECTORS=1 to regenerate", errorDetailWireVectorsPath)
	}
}

// TestErrorDetailWireCorpusReplay decodes every committed value with the generated code
// and requires the committed proto-JSON, so the corpus Go emits is one Go also reads.
func TestErrorDetailWireCorpusReplay(t *testing.T) {
	for _, v := range buildErrorDetailWireVectors(t) {
		raw, err := base64.RawStdEncoding.DecodeString(v.Value)
		if err != nil {
			t.Fatalf("%s: value is not unpadded base64: %v", v.Name, err)
		}
		var detail forav1.ErrorDetail
		if err := proto.Unmarshal(raw, &detail); err != nil {
			t.Fatalf("%s: decode: %v", v.Name, err)
		}
		if got := protoJSONOf(&detail); !reflect.DeepEqual(got, v.Detail) {
			t.Errorf("%s: detail = %v, want %v", v.Name, got, v.Detail)
		}
	}
}

// errorDetailWireTables walks the ErrorDetail subtree of the compiled descriptor.
func errorDetailWireTables() (map[string][]wireField, map[string]map[string]string) {
	messages := map[string][]wireField{}
	enums := map[string]map[string]string{}
	var walk func(md protoreflect.MessageDescriptor)
	walk = func(md protoreflect.MessageDescriptor) {
		name := string(md.FullName())
		if _, seen := messages[name]; seen {
			return
		}
		messages[name] = []wireField{}
		fields := md.Fields()
		out := make([]wireField, 0, fields.Len())
		for i := 0; i < fields.Len(); i++ {
			fd := fields.Get(i)
			f := wireField{Name: string(fd.Name()), Number: int(fd.Number()), Kind: fd.Kind().String()}
			switch {
			case fd.IsMap():
				f.Kind = "map"
				f.MapKey = fd.MapKey().Kind().String()
				f.MapValue = fd.MapValue().Kind().String()
			case fd.Kind() == protoreflect.EnumKind:
				f.Type = string(fd.Enum().FullName())
				enums[f.Type] = enumTable(fd.Enum())
			case fd.Kind() == protoreflect.MessageKind:
				f.Type = string(fd.Message().FullName())
				walk(fd.Message())
			}
			f.Repeated = fd.IsList()
			out = append(out, f)
		}
		sort.Slice(out, func(a, b int) bool { return out[a].Number < out[b].Number })
		messages[name] = out
	}
	walk((&forav1.ErrorDetail{}).ProtoReflect().Descriptor())
	return messages, enums
}

func enumTable(ed protoreflect.EnumDescriptor) map[string]string {
	values := ed.Values()
	out := make(map[string]string, values.Len())
	for i := 0; i < values.Len(); i++ {
		v := values.Get(i)
		out[strconv.Itoa(int(v.Number()))] = string(v.Name())
	}
	return out
}

func buildErrorDetailWireVectors(t *testing.T) []wireVector {
	t.Helper()
	var out []wireVector
	add := func(name string, raw []byte) {
		var detail forav1.ErrorDetail
		if err := proto.Unmarshal(raw, &detail); err != nil {
			t.Fatalf("%s: the corpus value does not decode: %v", name, err)
		}
		out = append(out, wireVector{
			Name: name, Value: base64.RawStdEncoding.EncodeToString(raw), Detail: protoJSONOf(&detail),
		})
	}
	for _, c := range everyFieldDetails() {
		add(c.name, deterministic(t, c.detail))
	}

	// restriction_mismatches written one tag per element. proto3 packs a repeated enum,
	// and a conforming decoder accepts both forms.
	unpacked := deterministic(t, &forav1.ErrorDetail{Domain: exchangeDomain})
	denial := protowire.AppendTag(nil, 1, protowire.VarintType)
	denial = protowire.AppendVarint(denial, uint64(forav1.DenialReason_DENIAL_REASON_RESTRICTION_NOT_SATISFIED))
	for _, k := range []forav1.RestrictionKind{forav1.RestrictionKind_RESTRICTION_KIND_USER_TYPE, forav1.RestrictionKind_RESTRICTION_KIND_OTHER} {
		denial = protowire.AppendTag(denial, 2, protowire.VarintType)
		denial = protowire.AppendVarint(denial, uint64(k))
	}
	unpacked = protowire.AppendTag(unpacked, 10, protowire.BytesType)
	unpacked = protowire.AppendBytes(unpacked, denial)
	add("unpacked_repeated_enum", unpacked)

	// A singular field written twice: the last value is the field's value.
	twice := protowire.AppendTag(nil, 2, protowire.BytesType)
	twice = protowire.AppendString(twice, "first.domain")
	twice = protowire.AppendTag(twice, 2, protowire.BytesType)
	twice = protowire.AppendString(twice, exchangeDomain)
	add("singular_field_last_value_wins", twice)

	// Unknown fields of every wire type, at the top level and inside a reason message.
	// A decoder skips each one by its wire type and keeps reading.
	unknown := func(b []byte) []byte {
		b = protowire.AppendTag(b, 99, protowire.VarintType)
		b = protowire.AppendVarint(b, 300)
		b = protowire.AppendTag(b, 98, protowire.BytesType)
		b = protowire.AppendString(b, "future field")
		b = protowire.AppendTag(b, 97, protowire.Fixed32Type)
		b = protowire.AppendFixed32(b, 7)
		b = protowire.AppendTag(b, 96, protowire.Fixed64Type)
		return protowire.AppendFixed64(b, 9)
	}
	inner := unknown(deterministic(t, &forav1.DisputeFailure{
		Reason: forav1.DisputeFailureReason_DISPUTE_FAILURE_REASON_DUPLICATE,
	}))
	withUnknown := unknown(deterministic(t, &forav1.ErrorDetail{Domain: exchangeDomain, Message: "dup"}))
	withUnknown = protowire.AppendTag(withUnknown, 13, protowire.BytesType)
	withUnknown = protowire.AppendBytes(withUnknown, inner)
	add("unknown_fields_skipped", withUnknown)

	add("empty_detail", nil)
	return out
}

type detailCase struct {
	name   string
	detail *forav1.ErrorDetail
}

// everyFieldDetails sets every field of every reason message, one family per vector,
// with the shared ErrorDetail fields and a two-entry metadata map on each.
func everyFieldDetails() []detailCase {
	base := func(msg string) *forav1.ErrorDetail {
		return &forav1.ErrorDetail{
			Domain:   exchangeDomain,
			Message:  msg,
			Metadata: map[string]string{"retryAfterSeconds": "30", "region": "eu"},
		}
	}
	offerID, exchange := "offer-7", "exchange.example:8443"
	denial := base("restriction not satisfied")
	denial.Reason = &forav1.ErrorDetail_TransactionDenial{TransactionDenial: &forav1.TransactionDenial{
		Reason: forav1.DenialReason_DENIAL_REASON_RESTRICTION_NOT_SATISFIED,
		RestrictionMismatches: []forav1.RestrictionKind{
			forav1.RestrictionKind_RESTRICTION_KIND_FUNCTION, forav1.RestrictionKind_RESTRICTION_KIND_GEOGRAPHY,
		},
		OfferId:  &offerID,
		Exchange: &exchange,
	}}
	catalog := base("entries rejected")
	catalog.Reason = &forav1.ErrorDetail_CatalogRejection{CatalogRejection: &forav1.CatalogRejection{
		Reason:        forav1.CatalogRejectionReason_CATALOG_REJECTION_REASON_UNKNOWN_VOCAB_TOKEN,
		RejectedPaths: []string{"/a", "/b/c"},
	}}
	registration := base("registration data rejected")
	registration.Reason = &forav1.ErrorDetail_RegistrationFailure{RegistrationFailure: &forav1.RegistrationFailure{
		Reason: forav1.RegistrationFailureReason_REGISTRATION_FAILURE_REASON_INVALID_REGISTRATION_DATA,
		FieldErrors: []*forav1.RegistrationFieldError{
			{Path: "/operator/legal_name", Error: "required property is missing"},
			{Path: "/contact/email", Error: "does not match format \"email\""},
		},
	}}
	dispute := base("dispute window closed")
	dispute.Reason = &forav1.ErrorDetail_DisputeFailure{DisputeFailure: &forav1.DisputeFailure{
		Reason: forav1.DisputeFailureReason_DISPUTE_FAILURE_REASON_WINDOW_EXPIRED,
	}}
	domain := base("challenge expired")
	domain.Reason = &forav1.ErrorDetail_DomainVerificationFailure{DomainVerificationFailure: &forav1.DomainVerificationFailure{
		Reason: forav1.DomainVerificationFailureReason_DOMAIN_VERIFICATION_FAILURE_REASON_CHALLENGE_EXPIRED,
	}}
	retrieval := base("thumbprint mismatch")
	retrieval.Reason = &forav1.ErrorDetail_RetrievalAuthFailure{RetrievalAuthFailure: &forav1.RetrievalAuthFailure{
		Reason: forav1.RetrievalAuthFailureReason_RETRIEVAL_AUTH_FAILURE_REASON_THUMBPRINT_MISMATCH,
	}}
	usage := base("missing required fields")
	usage.Reason = &forav1.ErrorDetail_UsageReportRejection{UsageReportRejection: &forav1.UsageReportRejection{
		Reason: forav1.UsageReportRejectionReason_USAGE_REPORT_REJECTION_REASON_MISSING_REQUIRED_FIELDS,
	}}
	auth := base("signature does not verify")
	auth.Reason = &forav1.ErrorDetail_RequestAuthFailure{RequestAuthFailure: &forav1.RequestAuthFailure{
		Reason: forav1.RequestAuthFailureReason_REQUEST_AUTH_FAILURE_REASON_SIGNATURE_INVALID,
	}}
	return []detailCase{
		{"transaction_denial_every_field", denial},
		{"catalog_rejection_every_field", catalog},
		{"registration_failure_every_field", registration},
		{"dispute_failure_every_field", dispute},
		{"domain_verification_failure_every_field", domain},
		{"retrieval_auth_failure_every_field", retrieval},
		{"usage_report_rejection_every_field", usage},
		{"request_auth_failure_every_field", auth},
	}
}

func deterministic(t *testing.T, m proto.Message) []byte {
	t.Helper()
	b, err := proto.MarshalOptions{Deterministic: true}.Marshal(m)
	if err != nil {
		t.Fatalf("marshal %T: %v", m, err)
	}
	return b
}

// requireEveryFieldSet fails unless every field of every message in the ErrorDetail
// subtree is populated in at least one vector — the property that makes the vectors,
// together with the table check, a complete statement of the decoding.
func requireEveryFieldSet(t *testing.T, vectors []wireVector) {
	t.Helper()
	seen := map[protoreflect.FullName]bool{}
	var mark func(m protoreflect.Message)
	mark = func(m protoreflect.Message) {
		m.Range(func(fd protoreflect.FieldDescriptor, v protoreflect.Value) bool {
			seen[fd.FullName()] = true
			switch {
			case fd.IsList() && fd.Kind() == protoreflect.MessageKind:
				for i := 0; i < v.List().Len(); i++ {
					mark(v.List().Get(i).Message())
				}
			case !fd.IsList() && !fd.IsMap() && fd.Kind() == protoreflect.MessageKind:
				mark(v.Message())
			}
			return true
		})
	}
	for _, v := range vectors {
		raw, err := base64.RawStdEncoding.DecodeString(v.Value)
		if err != nil {
			t.Fatalf("%s: %v", v.Name, err)
		}
		var detail forav1.ErrorDetail
		if err := proto.Unmarshal(raw, &detail); err != nil {
			t.Fatalf("%s: %v", v.Name, err)
		}
		mark(detail.ProtoReflect())
	}
	var check func(md protoreflect.MessageDescriptor, done map[protoreflect.FullName]bool)
	check = func(md protoreflect.MessageDescriptor, done map[protoreflect.FullName]bool) {
		if done[md.FullName()] {
			return
		}
		done[md.FullName()] = true
		for i := 0; i < md.Fields().Len(); i++ {
			fd := md.Fields().Get(i)
			if !seen[fd.FullName()] {
				t.Errorf("no vector sets %s; add one before the JSON decoders can be trusted with it", fd.FullName())
			}
			if fd.Kind() == protoreflect.MessageKind && !fd.IsMap() {
				check(fd.Message(), done)
			}
		}
	}
	check((&forav1.ErrorDetail{}).ProtoReflect().Descriptor(), map[protoreflect.FullName]bool{})
}
