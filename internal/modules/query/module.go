// Package query serves the IAM and STS APIs: one route, POST /, that
// dispatches on the service the request's credential is scoped to and the
// operation its Action names, as the AWS Query protocol does.
package query

import (
	"context"
	"errors"
	"net/http"

	"github.com/gasmod/gas"
	"tule.dev/sigv4"

	"tule.dev/identity/internal/contracts"
	"tule.dev/identity/internal/queryapi"
)

const moduleName = "tule/modules/query"

// Module registers the API route and serves the operations behind it.
type Module struct {
	router   *gas.Router
	store    contracts.IdentityProvider
	accounts contracts.AccountDirectory
	handlers map[*queryapi.Service]map[string]handler
}

// call is one request to an operation: its parameters and who signed it.
type call struct {
	params queryapi.Params
	caller *contracts.Principal
	svc    *queryapi.Service
	op     string
}

// handler serves one operation. Returning an error leaves the response to the
// dispatcher, which renders it as an error document of the call's service.
type handler func(gas.Context, *call) error

// NewModule returns a Module serving from store, asking accounts about the
// accounts AssumeRole targets. It registers its route when the app
// initializes it.
func NewModule(
	router *gas.Router,
	store contracts.IdentityProvider,
	accounts contracts.AccountDirectory,
) *Module {
	m := &Module{router: router, store: store, accounts: accounts}
	m.handlers = map[*queryapi.Service]map[string]handler{
		queryapi.IAM: {
			"CreateUser":           m.createUser,
			"GetUser":              m.getUser,
			"ListUsers":            m.listUsers,
			"DeleteUser":           m.deleteUser,
			"CreateAccessKey":      m.createAccessKey,
			"ListAccessKeys":       m.listAccessKeys,
			"UpdateAccessKey":      m.updateAccessKey,
			"DeleteAccessKey":      m.deleteAccessKey,
			"GetAccessKeyLastUsed": m.getAccessKeyLastUsed,
			"TagUser":              m.tagUser,
			"UntagUser":            m.untagUser,
			"ListUserTags":         m.listUserTags,
		},
		queryapi.STS: {
			"GetCallerIdentity": m.getCallerIdentity,
			"GetAccessKeyInfo":  m.getAccessKeyInfo,
			"AssumeRole":        m.assumeRole,
		},
	}
	return m
}

// Name identifies the module to gas.
func (m *Module) Name() string {
	return moduleName
}

// Init registers the module's route.
func (m *Module) Init(context.Context) error {
	// The Query protocol puts every operation on POST /, so there is one
	// route and the operation comes from the body.
	m.router.Handle(m, http.MethodPost, "/", m.dispatch)
	return nil
}

// Close releases nothing; the module holds no resources of its own.
func (m *Module) Close(context.Context) error {
	return nil
}

// dispatch serves the operation the request names, for the service of the
// credential scope the signature verified, which the signature middleware
// puts on the context. An Action this service does not serve for that
// service and the request's version, whether or not AWS has it, is answered
// as an invalid action, as AWS answers one it does not know: an IAM
// operation signed for STS included.
func (m *Module) dispatch(ctx gas.Context) error {
	r := ctx.Request()
	svc := queryapi.ServiceFrom(r.Context())

	if err := r.ParseForm(); err != nil {
		return queryapi.WriteError(ctx, svc, queryapi.ErrMalformedQueryString())
	}
	params := queryapi.Params(r.Form)
	op, ok := params.Get("Action")
	if !ok || op == "" {
		return queryapi.WriteError(ctx, svc, queryapi.ErrMissingAction())
	}
	version, _ := params.Get("Version")

	h, ok := m.handlers[svc][op]
	if !ok || version != svc.Version {
		return queryapi.WriteError(ctx, svc, queryapi.ErrInvalidAction(op, version))
	}

	caller, err := m.callerOf(ctx)
	if err != nil {
		return queryapi.WriteError(ctx, svc, err)
	}
	if err = h(ctx, &call{params: params, caller: caller, svc: svc, op: op}); err != nil {
		return queryapi.WriteError(ctx, svc, err)
	}
	return nil
}

// callerOf returns the principal that signed the request. The signature has
// verified, so the key is one the store knows; a key deleted since is
// refused as AWS refuses an unknown one.
func (m *Module) callerOf(ctx gas.Context) (*contracts.Principal, error) {
	p, ok := sigv4.PrincipalFrom(ctx.Request().Context())
	if !ok {
		return nil, errors.New("query: the request carries no verified principal")
	}
	caller, err := m.store.Principal(ctx, p.AccessKeyID)
	if errors.Is(err, contracts.ErrAccessKeyNotFound) {
		return nil, queryapi.NewError(http.StatusForbidden, queryapi.CodeInvalidClientTokenID,
			"The security token included in the request is invalid.")
	}
	return caller, err
}

// write sends result as the call's result.
func write(ctx gas.Context, c *call, result any) error {
	return queryapi.Write(ctx, c.svc, c.op, result)
}
