package vectorio

import (
	"errors"
	"fmt"

	forav1 "github.com/FORA-Protocol/protocol/gen/go/fora/v1"
)

// TransactionRequest is the request the acceptance tests of more than one package
// build: requester r, idempotency key "idem", and one item per offer, in order. A nil
// offer is an item that carries no offer.
func TransactionRequest(r *forav1.Requester, offers ...*forav1.Offer) *forav1.TransactionRequest {
	req := &forav1.TransactionRequest{Requester: r, IdempotencyKey: "idem"}
	for _, o := range offers {
		req.Items = append(req.Items, &forav1.TransactionItem{Offer: o})
	}
	return req
}

// ReasonProjection names the typed reason a detail carries the way the error-detail
// corpora record it: field is the name of the ErrorDetail `reason` oneof member that is
// set, and enum is the name of reason, the value helpers.Reason read out of that member.
// Both are "" when reason is nil. The member name is read off the descriptor, so a
// reason family added to the contract is projected under its own name.
func ReasonProjection(detail *forav1.ErrorDetail, reason any) (field, enum string, err error) {
	if reason == nil {
		return "", "", nil
	}
	named, ok := reason.(fmt.Stringer)
	if !ok {
		return "", "", fmt.Errorf("typed reason %T does not name itself", reason)
	}
	m := detail.ProtoReflect()
	od := m.Descriptor().Oneofs().ByName("reason")
	if od == nil {
		return "", "", errors.New("ErrorDetail has no `reason` oneof")
	}
	fd := m.WhichOneof(od)
	if fd == nil {
		return "", "", errors.New("the `reason` oneof is unset on a detail that named a reason")
	}
	return string(fd.Name()), named.String(), nil
}
