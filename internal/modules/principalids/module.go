// Package principalids serves the principal-ID endpoint, through which a
// Tule service binds the IAM user and role ARNs of a resource-based policy to
// unique IDs when the policy is saved, and shows a bound policy with the
// current ARNs: it resolves user and role ARNs to unique IDs, and unique IDs
// to ARNs, in batches. It is not an AWS API; tule.dev/identity/principals
// is its client and holds its wire types.
//
// The app verifies every call to it against the root user's key alone,
// before this module reads anything, as it verifies the signing-key
// endpoint's.
package principalids

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"

	"github.com/gasmod/gas"

	"tule.dev/identity/internal/contracts"
	"tule.dev/identity/internal/httpx"
	"tule.dev/identity/principals"
)

const moduleName = "tule/modules/principalids"

// Module registers the endpoint's route and serves it.
type Module struct {
	router *gas.Router
	store  contracts.IdentityProvider
}

// NewModule returns a Module answering from store. It registers its route
// when the app initializes it.
func NewModule(router *gas.Router, store contracts.IdentityProvider) *Module {
	return &Module{router: router, store: store}
}

// Name identifies the module to gas.
func (m *Module) Name() string {
	return moduleName
}

// Init registers the module's route.
func (m *Module) Init(context.Context) error {
	m.router.Handle(m, http.MethodPost, principals.Path, m.resolve)
	return nil
}

// Close releases nothing; the module holds no resources of its own.
func (m *Module) Close(context.Context) error {
	return nil
}

// resolve answers with the unique ID of each user and role ARN the request
// names that a user or role has now, and the current ARN of each unique ID
// a user or role has.
func (m *Module) resolve(ctx gas.Context) error {
	var req principals.Request
	if err := json.NewDecoder(ctx.Request().Body).Decode(&req); err != nil {
		return writeInvalid(ctx, "The body is not a JSON principal-ID request.")
	}
	if n := len(req.ARNs) + len(req.IDs); n > principals.MaxBatch {
		return writeInvalid(ctx, "The request names "+strconv.Itoa(n)+
			" ARNs and IDs; at most "+strconv.Itoa(principals.MaxBatch)+" are allowed.")
	}
	for _, arn := range req.ARNs {
		if !principals.IsBindable(arn) {
			return writeInvalid(ctx, strconv.Quote(arn)+" is not a user or role ARN.")
		}
	}
	for _, id := range req.IDs {
		if !principals.IsUniqueID(id) {
			return writeInvalid(ctx, strconv.Quote(id)+" is not a user or role unique ID.")
		}
	}

	ids, err := m.store.PrincipalIDs(ctx, req.ARNs)
	if err != nil {
		return writeFailure(ctx, err)
	}
	arns, err := m.store.PrincipalARNs(ctx, req.IDs)
	if err != nil {
		return writeFailure(ctx, err)
	}
	return write(ctx, http.StatusOK, principals.Response{IDs: ids, ARNs: arns})
}

func writeInvalid(ctx gas.Context, msg string) error {
	return write(ctx, http.StatusBadRequest, principals.ErrorResponse{
		Code: principals.CodeInvalidRequest, Message: msg,
	})
}

func writeFailure(ctx gas.Context, err error) error {
	httpx.Logger(ctx).Error("principal ID resolution failed").Err("error", err).Send()
	return write(ctx, http.StatusInternalServerError, principals.ErrorResponse{
		Code: "InternalFailure", Message: "The principals could not be resolved.",
	})
}

func write(ctx gas.Context, status int, v any) error {
	body, err := json.Marshal(v)
	if err != nil {
		return fmt.Errorf("encode the response: %w", err)
	}
	w := ctx.ResponseWriter()
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if _, err = w.Write(body); err != nil {
		httpx.Logger(ctx).Warn("failed to write response").Err("error", err).Send()
	}
	return nil
}
