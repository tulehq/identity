// Package servicerole serves the assume-role endpoint, through which a Tule
// service assumes a role as an AWS service principal, as Lambda assumes a
// function's execution role. It is not an AWS API;
// tule.dev/identity/servicerole is its client and holds its wire types.
//
// The app verifies every call to it against the root user's key alone,
// before this module reads anything, as it verifies the signing-key
// endpoint's.
package servicerole

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/gasmod/gas"
	"tule.dev/policy"

	"tule.dev/identity/internal/contracts"
	"tule.dev/identity/internal/httpx"
	"tule.dev/identity/internal/queryapi"
	"tule.dev/identity/internal/trustdoc"
	"tule.dev/identity/servicerole"
)

const moduleName = "tule/modules/servicerole"

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
	m.router.Handle(m, http.MethodPost, servicerole.Path, m.assumeRole)
	return nil
}

// Close releases nothing; the module holds no resources of its own.
func (m *Module) Close(context.Context) error {
	return nil
}

// refusal is a call the endpoint refuses, with the status and code of its
// answer.
type refusal struct {
	code    string
	message string
	status  int
}

func (r *refusal) Error() string { return r.code + ": " + r.message }

func invalid(msg string) *refusal {
	return &refusal{
		status:  http.StatusBadRequest,
		code:    servicerole.CodeInvalidRequest,
		message: msg,
	}
}

func invalidDuration(msg string) *refusal {
	return &refusal{
		status:  http.StatusBadRequest,
		code:    servicerole.CodeInvalidDuration,
		message: msg,
	}
}

// assumeRole answers with a session of the role the request names, when the
// role's trust policy allows the service principal sts:AssumeRole. The
// trust policy is evaluated as AssumeRole evaluates it, its user and role
// principals bound to their unique IDs, which name no service; identity
// policies are not, as a service principal has none. Nothing about the role
// changes.
func (m *Module) assumeRole(ctx gas.Context) error {
	var req servicerole.Request
	if err := json.NewDecoder(ctx.Request().Body).Decode(&req); err != nil {
		return writeRefusal(ctx, invalid("The body is not a JSON assume-role request."))
	}
	duration, rErr := checkRequest(&req)
	if rErr != nil {
		return writeRefusal(ctx, rErr)
	}

	role, err := m.trustedRole(ctx, &req)
	if err != nil {
		return writeFailure(ctx, err)
	}
	if duration > role.MaxSessionDuration {
		return writeRefusal(ctx, invalidDuration("The requested DurationSeconds exceeds the "+
			"MaxSessionDuration set for this role."))
	}
	rs, err := m.store.CreateRoleSession(ctx, contracts.CreateRoleSessionInput{
		Role:        role,
		SessionName: req.RoleSessionName,
		Duration:    time.Duration(duration) * time.Second,
	})
	if err != nil {
		return writeFailure(ctx, err)
	}
	return write(ctx, http.StatusOK, servicerole.Session{
		Credentials: servicerole.Credentials{
			Expiration:      rs.Expiration,
			AccessKeyID:     rs.AccessKeyID,
			SecretAccessKey: rs.SecretAccessKey,
			SessionToken:    rs.SessionToken,
		},
		AssumedRoleUser: servicerole.AssumedRoleUser{
			AssumedRoleID: rs.AssumedRoleID,
			Arn:           rs.ARN,
		},
	})
}

// checkRequest checks the request's fields as AssumeRole checks its
// parameters, and returns the session duration it asks for.
func checkRequest(req *servicerole.Request) (int, *refusal) {
	if err := queryapi.RoleARN.Check("RoleArn", req.RoleArn); err != nil {
		return 0, invalid(err.Error())
	}
	if _, _, _, ok := contracts.ParseRoleARN(req.RoleArn); !ok {
		return 0, invalid("RoleArn " + req.RoleArn + " is not a role ARN.")
	}
	if err := queryapi.RoleSessionName.Check("RoleSessionName", req.RoleSessionName); err != nil {
		return 0, invalid(err.Error())
	}
	if !servicerole.IsServicePrincipal(req.ServicePrincipal) {
		return 0, invalid("ServicePrincipal " + strconv.Quote(req.ServicePrincipal) +
			" is not a service principal such as lambda.amazonaws.com.")
	}
	if r := checkSource(req); r != nil {
		return 0, r
	}
	return checkDuration(req.DurationSeconds)
}

// checkSource checks the optional SourceArn and SourceAccount.
func checkSource(req *servicerole.Request) *refusal {
	if req.SourceArn != "" && !servicerole.IsSourceArn(req.SourceArn) {
		return invalid("SourceArn " + strconv.Quote(req.SourceArn) + " is not an ARN.")
	}
	if req.SourceAccount != "" && !servicerole.IsAccountID(req.SourceAccount) {
		return invalid("SourceAccount " + strconv.Quote(req.SourceAccount) +
			" is not a 12-digit account ID.")
	}
	return nil
}

// checkDuration returns the session duration DurationSeconds asks for, an
// hour for 0.
func checkDuration(d int) (int, *refusal) {
	switch {
	case d == 0:
		return contracts.DefaultSessionDuration, nil
	case d < contracts.MinSessionDuration || d > contracts.MaxSessionDuration:
		return 0, invalidDuration(fmt.Sprintf("DurationSeconds must be %d to %d.",
			contracts.MinSessionDuration, contracts.MaxSessionDuration))
	default:
		return d, nil
	}
}

// trustedRole returns the role the request names, matched with its case as
// AssumeRole matches it, when its trust policy allows the service.
func (m *Module) trustedRole(ctx gas.Context, req *servicerole.Request) (*contracts.Role, error) {
	account, path, name, _ := contracts.ParseRoleARN(req.RoleArn)
	noSuchRole := &refusal{
		status: http.StatusNotFound, code: servicerole.CodeNoSuchRole,
		message: "The role " + req.RoleArn + " does not exist.",
	}
	role, err := m.store.GetRole(ctx, account, name)
	switch {
	case errors.Is(err, contracts.ErrRoleNotFound):
		return nil, noSuchRole
	case err != nil:
		return nil, fmt.Errorf("servicerole: read the role: %w", err)
	case role.Name != name || role.Path != path:
		return nil, noSuchRole
	}

	notTrusted := &refusal{
		status: http.StatusForbidden, code: servicerole.CodeNotTrusted,
		message: "The trust policy of " + role.ARN + " does not allow " +
			req.ServicePrincipal + " to assume it.",
	}
	trust, ok, err := trustdoc.Parse(role, "", httpx.Logger(ctx))
	switch {
	case err != nil:
		return nil, err
	case !ok:
		return nil, notTrusted
	}
	now := time.Now().UTC()
	keys := map[string][]string{
		"sts:RoleSessionName": {req.RoleSessionName},
		"aws:CurrentTime":     {now.Format(time.RFC3339)},
		"aws:EpochTime":       {strconv.FormatInt(now.Unix(), 10)},
	}
	// The resource the service acts for, as a service supplies it.
	if req.SourceArn != "" {
		keys["aws:SourceArn"] = []string{req.SourceArn}
	}
	if req.SourceAccount != "" {
		keys["aws:SourceAccount"] = []string{req.SourceAccount}
	}
	if policy.TrustMatch(trust, role.AccountID, "sts:AssumeRole", req.ServicePrincipal,
		keys).Decision != policy.Allow {
		return nil, notTrusted
	}
	return role, nil
}

// writeFailure answers a refusal with its code, and any other failure as
// internal.
func writeFailure(ctx gas.Context, err error) error {
	var r *refusal
	if errors.As(err, &r) {
		return writeRefusal(ctx, r)
	}
	httpx.Logger(ctx).Error("assume-role failed").Err("error", err).Send()
	return write(ctx, http.StatusInternalServerError, servicerole.ErrorResponse{
		Code: "InternalFailure", Message: "The role could not be assumed.",
	})
}

func writeRefusal(ctx gas.Context, r *refusal) error {
	return write(ctx, r.status, servicerole.ErrorResponse{Code: r.code, Message: r.message})
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
