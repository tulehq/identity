// Package signingkey serves the signing-key endpoint the other Tule services
// verify requests through: given the scope of a request's credential, it
// answers with the derived signing key for that scope and the principal the
// key belongs to: at version 2, with whether it is the root user and the
// identity policies in effect for it, and at version 3, with the values of
// its condition keys too. It is not an AWS API; tule.dev/identity/keysource
// is its client and holds its wire types.
//
// The app verifies every call to it against the root user's key alone,
// before this module reads anything, so only a holder of that key can ask.
package signingkey

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/gasmod/gas"
	"tule.dev/sigv4"

	"tule.dev/identity/internal/contracts"
	"tule.dev/identity/internal/httpx"
	"tule.dev/identity/keysource"
)

const moduleName = "tule/modules/signingkey"

// codeInvalidRequest is the code of a body that is not a scope.
const codeInvalidRequest = "InvalidRequest"

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
	m.router.Handle(m, http.MethodPost, keysource.Path, m.signingKey)
	return nil
}

// Close releases nothing; the module holds no resources of its own.
func (m *Module) Close(context.Context) error {
	return nil
}

// signingKey answers with the signing key of the scope in the body, and
// records the key's use with the scope's service and region. A request at
// keysource.VersionAttributes or later is answered at that version, with
// the principal's Root, Policies and condition key values; one at
// keysource.VersionPolicies, at that version, with Root and Policies only;
// an earlier one, as v0.1.0 answered it. The use is recorded when the key
// is handed out: the caller checks the signature after, so a request it
// then refuses is recorded too.
func (m *Module) signingKey(ctx gas.Context) error {
	var req keysource.Request
	if err := json.NewDecoder(ctx.Request().Body).Decode(&req); err != nil {
		return writeError(ctx, http.StatusBadRequest, codeInvalidRequest,
			"The body is not a JSON credential scope.")
	}
	if req.AccessKeyID == "" || req.Date == "" || req.Region == "" || req.Service == "" {
		return writeError(ctx, http.StatusBadRequest, codeInvalidRequest,
			"AccessKeyId, Date, Region and Service are required.")
	}

	key, err := m.store.SigningKey(ctx, req.Scope())
	if err != nil {
		return writeKeyError(ctx, err)
	}
	if err = m.store.RecordKeyUse(ctx, req.AccessKeyID, req.Service, req.Region); err != nil {
		return writeKeyError(ctx, err)
	}
	out := keysource.Response{
		Principal: keysource.Principal{
			AccountID:   key.Principal.AccountID,
			ARN:         key.Principal.ARN,
			AccessKeyID: key.Principal.AccessKeyID,
		},
		SigningKey: key.Signing,
	}
	p := key.Principal
	if req.Version >= keysource.VersionPolicies {
		out.Version = keysource.VersionPolicies
		out.Principal.Root = p.Root
		out.Principal.Policies = p.Policies
	}
	if req.Version >= keysource.VersionAttributes {
		out.Version = keysource.VersionAttributes
		out.Principal.PrincipalARN = p.PrincipalARN
		out.Principal.UserID = p.UserID
		out.Principal.PrincipalType = string(p.Type)
		out.Principal.Tags = p.Tags
	}
	return write(ctx, http.StatusOK, out)
}

// writeKeyError answers a lookup that found no key with the code the client
// maps to the sigv4 error, and any other failure as internal.
func writeKeyError(ctx gas.Context, err error) error {
	refusals := []struct {
		err  error
		code string
	}{
		// Inactive first: it wraps sigv4.ErrUnknownAccessKey.
		{contracts.ErrInactiveAccessKey, keysource.CodeInactiveAccessKey},
		{sigv4.ErrUnknownAccessKey, keysource.CodeUnknownAccessKey},
		{sigv4.ErrInvalidSessionToken, keysource.CodeInvalidSessionToken},
		{sigv4.ErrExpiredSessionToken, keysource.CodeExpiredSessionToken},
	}
	for _, r := range refusals {
		if errors.Is(err, r.err) {
			return writeError(ctx, http.StatusBadRequest, r.code, err.Error())
		}
	}
	httpx.Logger(ctx).Error("signing key lookup failed").Err("error", err).Send()
	return writeError(ctx, http.StatusInternalServerError, "InternalFailure",
		"The signing key could not be looked up.")
}

func writeError(ctx gas.Context, status int, code, msg string) error {
	return write(ctx, status, keysource.ErrorResponse{Code: code, Message: msg})
}

// WriteHTTPError answers a call to an internal endpoint, this one or
// assume-role, that the app's verification refused, with the sigv4 Kind as
// the code.
func WriteHTTPError(w http.ResponseWriter, r *http.Request, err error) {
	status, code := http.StatusInternalServerError, "InternalFailure"
	var sigErr *sigv4.Error
	if errors.As(err, &sigErr) && sigErr.Kind != sigv4.KindKeyLookupFailed {
		status, code = http.StatusForbidden, sigErr.Kind.String()
	} else {
		httpx.Logger(r.Context()).Error("request failed").Err("error", err).Send()
	}
	body, mErr := json.Marshal(keysource.ErrorResponse{Code: code, Message: errMessage(err)})
	if mErr != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	writeBody(w, r, status, body)
}

func errMessage(err error) string {
	var sigErr *sigv4.Error
	if errors.As(err, &sigErr) {
		return sigErr.Message
	}
	return "The request could not be served."
}

func write(ctx gas.Context, status int, v any) error {
	body, err := json.Marshal(v)
	if err != nil {
		return fmt.Errorf("encode the response: %w", err)
	}
	writeBody(ctx.ResponseWriter(), ctx.Request(), status, body)
	return nil
}

func writeBody(w http.ResponseWriter, r *http.Request, status int, body []byte) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if _, err := w.Write(body); err != nil {
		httpx.Logger(r.Context()).Warn("failed to write response").Err("error", err).Send()
	}
}
