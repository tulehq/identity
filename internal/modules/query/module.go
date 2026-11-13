// Package query serves the IAM and STS APIs: one route, POST /, that
// dispatches on the service the request's credential is scoped to and the
// operation its Action names, as the AWS Query protocol does.
package query

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	"github.com/gasmod/gas"
	"tule.dev/sigv4"

	"tule.dev/identity/internal/contracts"
	"tule.dev/identity/internal/orgkeys"
	"tule.dev/identity/internal/queryapi"
)

const moduleName = "tule/modules/query"

// Module registers the API route and serves the operations behind it.
type Module struct {
	router   *gas.Router
	store    contracts.IdentityProvider
	accounts contracts.AccountDirectory
	orgs     orgkeys.Source
	handlers map[*queryapi.Service]map[string]handler
}

// call is one request to an operation: its parameters, who signed it, as
// the store knows the principal and as the verifier reports it with its
// policies. authorized is set once the call is authorized.
type call struct {
	params     queryapi.Params
	caller     *contracts.Principal
	svc        *queryapi.Service
	tags       *tagsParam
	tagKeys    *tagKeysParam
	org        *orgkeys.Keys
	op         string
	signer     sigv4.Principal
	authorized bool
}

// tagsParam is the request's Tags as requestTags decoded them.
type tagsParam struct {
	err  error
	tags []contracts.Tag
	set  bool
}

// tagKeysParam is the request's TagKeys as requestTagKeys decoded them.
type tagKeysParam struct {
	err  error
	keys []string
}

// requestTags returns the request's Tags, decoded once for the call: the
// handler acts on, and the authorization's aws:RequestTag and aws:TagKeys
// describe, the same tags.
func (c *call) requestTags() ([]contracts.Tag, bool, error) {
	if c.tags == nil {
		tags, set, err := queryapi.Tags(c.params, "Tags")
		c.tags = &tagsParam{tags: tags, set: set, err: err}
	}
	return c.tags.tags, c.tags.set, c.tags.err
}

// requestTagKeys returns the request's TagKeys, decoded once for the call,
// as requestTags does Tags.
func (c *call) requestTagKeys() ([]string, error) {
	if c.tagKeys == nil {
		keys, err := queryapi.TagKeys(c.params, "TagKeys")
		c.tagKeys = &tagKeysParam{keys: keys, err: err}
	}
	return c.tagKeys.keys, c.tagKeys.err
}

// handler serves one operation. Returning an error leaves the response to the
// dispatcher, which renders it as an error document of the call's service.
type handler func(gas.Context, *call) error

// NewModule returns a Module serving from store, asking accounts about the
// accounts AssumeRole targets, and orgs for the callers' organization keys.
// It registers its route when the app initializes it.
func NewModule(
	router *gas.Router,
	store contracts.IdentityProvider,
	accounts contracts.AccountDirectory,
	orgs orgkeys.Source,
) *Module {
	m := &Module{router: router, store: store, accounts: accounts, orgs: orgs}
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

			"CreatePolicy":            m.createPolicy,
			"GetPolicy":               m.getPolicy,
			"ListPolicies":            m.listPolicies,
			"DeletePolicy":            m.deletePolicy,
			"CreatePolicyVersion":     m.createPolicyVersion,
			"GetPolicyVersion":        m.getPolicyVersion,
			"ListPolicyVersions":      m.listPolicyVersions,
			"DeletePolicyVersion":     m.deletePolicyVersion,
			"SetDefaultPolicyVersion": m.setDefaultPolicyVersion,

			"AttachUserPolicy":         m.attachPolicy(contracts.EntityUser),
			"DetachUserPolicy":         m.detachPolicy(contracts.EntityUser),
			"ListAttachedUserPolicies": m.listAttachedPolicies(contracts.EntityUser),
			"PutUserPolicy":            m.putInlinePolicy(contracts.EntityUser),
			"GetUserPolicy":            m.getInlinePolicy(contracts.EntityUser),
			"ListUserPolicies":         m.listInlinePolicies(contracts.EntityUser),
			"DeleteUserPolicy":         m.deleteInlinePolicy(contracts.EntityUser),

			"CreateRole":               m.createRole,
			"GetRole":                  m.getRole,
			"ListRoles":                m.listRoles,
			"UpdateRole":               m.updateRole,
			"UpdateAssumeRolePolicy":   m.updateAssumeRolePolicy,
			"DeleteRole":               m.deleteRole,
			"AttachRolePolicy":         m.attachPolicy(contracts.EntityRole),
			"DetachRolePolicy":         m.detachPolicy(contracts.EntityRole),
			"ListAttachedRolePolicies": m.listAttachedPolicies(contracts.EntityRole),
			"PutRolePolicy":            m.putInlinePolicy(contracts.EntityRole),
			"GetRolePolicy":            m.getInlinePolicy(contracts.EntityRole),
			"ListRolePolicies":         m.listInlinePolicies(contracts.EntityRole),
			"DeleteRolePolicy":         m.deleteInlinePolicy(contracts.EntityRole),
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

	c := &call{params: params, svc: svc, op: op}
	if err := m.identify(ctx, c); err != nil {
		return queryapi.WriteError(ctx, svc, err)
	}
	if err := h(ctx, c); err != nil {
		return queryapi.WriteError(ctx, svc, err)
	}
	return nil
}

// identify sets who signed the call's request. The signature has verified, so the key is one the store knows; a key
// deleted since is refused as AWS refuses an unknown one.
func (m *Module) identify(ctx gas.Context, c *call) error {
	rctx := ctx.Request().Context()
	p, ok := sigv4.PrincipalFrom(rctx)
	if !ok {
		return errors.New("query: the request carries no verified principal")
	}
	caller, err := m.store.Principal(ctx, p.AccessKeyID)
	if errors.Is(err, contracts.ErrAccessKeyNotFound) {
		return queryapi.NewError(http.StatusForbidden, queryapi.CodeInvalidClientTokenID,
			"The security token included in the request is invalid.")
	}
	if err != nil {
		return err
	}
	c.caller, c.signer = caller, p
	return nil
}

// write sends result as the call's result, once the call is authorized. A
// handler that reaches it without authorizing the call is a bug, refused
// rather than answered.
func write(ctx gas.Context, c *call, result any) error {
	if !c.authorized {
		return fmt.Errorf("query: %s answered without being authorized", c.op)
	}
	return queryapi.Write(ctx, c.svc, c.op, result)
}
