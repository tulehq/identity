package query

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/gasmod/gas"
	"tule.dev/policy"

	"tule.dev/identity/internal/contracts"
	"tule.dev/identity/internal/httpx"
	"tule.dev/identity/internal/queryapi"
)

// operation is how a request to an operation is authorized: the IAM action
// it is evaluated as, the resource ARN it acts on, and the condition keys it
// supplies beyond the global ones. always marks an operation AWS allows
// every principal, which is not evaluated.
type operation struct {
	resource func(m *Module, ctx gas.Context, c *call) (string, error)
	context  func(c *call) map[string][]string
	action   string
	always   bool
}

// operations is every routed operation's authorization, by service and
// operation: the action and resource type the Service Authorization
// Reference lists for it (the IAM and STS pages, and AWS's service reference
// JSON for iam and sts), with the resource's ARN in the reference's format.
// An action the reference lists no resource type for is evaluated on "*",
// which is the only Resource that allows it. A test holds every handler to
// an entry here.
var operations = map[*queryapi.Service]map[string]operation{
	queryapi.IAM: {
		"CreateUser": {
			action: "iam:CreateUser", resource: newUserResource, context: requestTagKeys,
		},
		"GetUser":              {action: "iam:GetUser", resource: targetUserResource},
		"ListUsers":            {action: "iam:ListUsers", resource: anyResource},
		"DeleteUser":           {action: "iam:DeleteUser", resource: userResource},
		"CreateAccessKey":      {action: "iam:CreateAccessKey", resource: targetUserResource},
		"ListAccessKeys":       {action: "iam:ListAccessKeys", resource: targetUserResource},
		"UpdateAccessKey":      {action: "iam:UpdateAccessKey", resource: targetUserResource},
		"DeleteAccessKey":      {action: "iam:DeleteAccessKey", resource: targetUserResource},
		"GetAccessKeyLastUsed": {action: "iam:GetAccessKeyLastUsed", resource: keyOwnerResource},
		"TagUser": {
			action:   "iam:TagUser",
			resource: userResource,
			context:  requestTagKeys,
		},
		"UntagUser": {
			action:   "iam:UntagUser",
			resource: userResource,
			context:  untagKeys,
		},
		"ListUserTags": {action: "iam:ListUserTags", resource: userResource},

		"CreatePolicy": {
			action: "iam:CreatePolicy", resource: newPolicyResource, context: requestTagKeys,
		},
		"GetPolicy":           {action: "iam:GetPolicy", resource: policyResource},
		"ListPolicies":        {action: "iam:ListPolicies", resource: anyResource},
		"DeletePolicy":        {action: "iam:DeletePolicy", resource: policyResource},
		"CreatePolicyVersion": {action: "iam:CreatePolicyVersion", resource: policyResource},
		"GetPolicyVersion":    {action: "iam:GetPolicyVersion", resource: policyResource},
		"ListPolicyVersions":  {action: "iam:ListPolicyVersions", resource: policyResource},
		"DeletePolicyVersion": {action: "iam:DeletePolicyVersion", resource: policyResource},
		"SetDefaultPolicyVersion": {
			action:   "iam:SetDefaultPolicyVersion",
			resource: policyResource,
		},

		"AttachUserPolicy": {
			action: "iam:AttachUserPolicy", resource: userResource, context: policyARNKey,
		},
		"DetachUserPolicy": {
			action: "iam:DetachUserPolicy", resource: userResource, context: policyARNKey,
		},
		"ListAttachedUserPolicies": {
			action:   "iam:ListAttachedUserPolicies",
			resource: userResource,
		},
		"PutUserPolicy":    {action: "iam:PutUserPolicy", resource: userResource},
		"GetUserPolicy":    {action: "iam:GetUserPolicy", resource: userResource},
		"ListUserPolicies": {action: "iam:ListUserPolicies", resource: userResource},
		"DeleteUserPolicy": {action: "iam:DeleteUserPolicy", resource: userResource},

		"CreateRole": {
			action: "iam:CreateRole", resource: newRoleResource, context: requestTagKeys,
		},
		"GetRole":                {action: "iam:GetRole", resource: roleResource},
		"ListRoles":              {action: "iam:ListRoles", resource: anyResource},
		"UpdateRole":             {action: "iam:UpdateRole", resource: roleResource},
		"UpdateAssumeRolePolicy": {action: "iam:UpdateAssumeRolePolicy", resource: roleResource},
		"DeleteRole":             {action: "iam:DeleteRole", resource: roleResource},
		"AttachRolePolicy": {
			action: "iam:AttachRolePolicy", resource: roleResource, context: policyARNKey,
		},
		"DetachRolePolicy": {
			action: "iam:DetachRolePolicy", resource: roleResource, context: policyARNKey,
		},
		"ListAttachedRolePolicies": {
			action:   "iam:ListAttachedRolePolicies",
			resource: roleResource,
		},
		"PutRolePolicy":    {action: "iam:PutRolePolicy", resource: roleResource},
		"GetRolePolicy":    {action: "iam:GetRolePolicy", resource: roleResource},
		"ListRolePolicies": {action: "iam:ListRolePolicies", resource: roleResource},
		"DeleteRolePolicy": {action: "iam:DeleteRolePolicy", resource: roleResource},
	},
	queryapi.STS: {
		// GetCallerIdentity needs no permission: "No permissions are
		// required to perform this operation" (the STS API reference), and
		// an explicit deny does not stop it.
		"GetCallerIdentity": {action: "sts:GetCallerIdentity", always: true},
		"GetAccessKeyInfo":  {action: "sts:GetAccessKeyInfo", resource: anyResource},
		"AssumeRole": {
			action: "sts:AssumeRole", resource: assumedRoleResource, context: sessionNameKey,
		},
	},
}

func anyResource(*Module, gas.Context, *call) (string, error) {
	return "*", nil
}

// userResource is the IAM user the request's UserName names, with its path
// when it exists, else with the default path.
func userResource(m *Module, ctx gas.Context, c *call) (string, error) {
	name, _ := c.params.Get("UserName")
	return m.userARN(ctx, c.caller.AccountID, name)
}

// targetUserResource is the user an operation with an optional UserName acts
// on: the named one, or the caller, which may be the root user.
func targetUserResource(m *Module, ctx gas.Context, c *call) (string, error) {
	if _, set := c.params.Get("UserName"); set {
		return userResource(m, ctx, c)
	}
	return c.caller.ARN, nil
}

func newUserResource(_ *Module, _ gas.Context, c *call) (string, error) {
	name, _ := c.params.Get("UserName")
	return contracts.UserARN(c.caller.AccountID, pathOrDefault(c, "Path"), name), nil
}

// keyOwnerResource is the user whose access key GetAccessKeyLastUsed asks
// about: the IAM user of the caller's account it belongs to, or the root
// user for its key. A key of no user of the account names the account's
// users, so the answer reveals no more than the caller may know.
func keyOwnerResource(m *Module, ctx gas.Context, c *call) (string, error) {
	keyID, _ := c.params.Get("AccessKeyId")
	p, err := m.store.Principal(ctx, keyID)
	switch {
	case errors.Is(err, contracts.ErrAccessKeyNotFound):
	case err != nil:
		return "", err
	case p.AccountID == c.caller.AccountID && p.Kind != contracts.PrincipalRoleSession:
		return p.ARN, nil
	}
	return contracts.UserARN(c.caller.AccountID, "/", ""), nil
}

func policyResource(_ *Module, _ gas.Context, c *call) (string, error) {
	arn, _ := c.params.Get("PolicyArn")
	return arn, nil
}

func newPolicyResource(_ *Module, _ gas.Context, c *call) (string, error) {
	name, _ := c.params.Get("PolicyName")
	return contracts.PolicyARN(c.caller.AccountID, pathOrDefault(c, "Path"), name), nil
}

// roleResource is the role the request's RoleName names, with its path when
// it exists, else with the default path.
func roleResource(m *Module, ctx gas.Context, c *call) (string, error) {
	name, _ := c.params.Get("RoleName")
	r, err := m.store.GetRole(ctx, c.caller.AccountID, name)
	switch {
	case errors.Is(err, contracts.ErrRoleNotFound):
		return contracts.RoleARN(c.caller.AccountID, "/", name), nil
	case err != nil:
		return "", err
	}
	return r.ARN, nil
}

func newRoleResource(_ *Module, _ gas.Context, c *call) (string, error) {
	name, _ := c.params.Get("RoleName")
	return contracts.RoleARN(c.caller.AccountID, pathOrDefault(c, "Path"), name), nil
}

// assumedRoleResource is the role AssumeRole names, as the request names it.
func assumedRoleResource(_ *Module, _ gas.Context, c *call) (string, error) {
	arn, _ := c.params.Get("RoleArn")
	return arn, nil
}

func pathOrDefault(c *call, field string) string {
	if p, _ := c.params.Get(field); p != "" {
		return p
	}
	return "/"
}

// policyARNKey supplies iam:PolicyARN, which the reference lists for the
// attach and detach actions.
func policyARNKey(c *call) map[string][]string {
	arn, _ := c.params.Get("PolicyArn")
	return map[string][]string{"iam:PolicyARN": {arn}}
}

// requestTagKeys supplies aws:RequestTag/<key> and aws:TagKeys from the
// request's Tags, which the reference lists for CreateUser, TagUser,
// CreatePolicy and CreateRole. The handler has validated them, from the
// same decoding.
func requestTagKeys(c *call) map[string][]string {
	tags, _, err := c.requestTags()
	if err != nil || len(tags) == 0 {
		return nil
	}
	keys := map[string][]string{}
	names := make([]string, 0, len(tags))
	for _, t := range tags {
		keys["aws:RequestTag/"+t.Key] = []string{t.Value}
		names = append(names, t.Key)
	}
	keys["aws:TagKeys"] = names
	return keys
}

// untagKeys supplies aws:TagKeys from UntagUser's TagKeys.
func untagKeys(c *call) map[string][]string {
	names, err := c.requestTagKeys()
	if err != nil || len(names) == 0 {
		return nil
	}
	return map[string][]string{"aws:TagKeys": names}
}

// sessionNameKey supplies sts:RoleSessionName for AssumeRole.
func sessionNameKey(c *call) map[string][]string {
	name, _ := c.params.Get("RoleSessionName")
	return map[string][]string{"sts:RoleSessionName": {name}}
}

// userARN is the ARN of the account's IAM user with the name: with its path
// when it exists, else with the default path, as the request carries none.
func (m *Module) userARN(ctx gas.Context, accountID, name string) (string, error) {
	u, err := m.store.GetUser(ctx, accountID, name)
	switch {
	case errors.Is(err, contracts.ErrUserNotFound):
		return contracts.UserARN(accountID, "/", name), nil
	case err != nil:
		return "", err
	}
	return u.ARN, nil
}

// authorize authorizes the call by its entry in operations, once its
// parameters are validated: the root user, and an operation every principal
// may call, are allowed; any other principal must have an identity policy
// that allows the action on the resource, and none that denies it.
// Handlers call it before they act; write refuses a call that was not
// authorized.
func (m *Module) authorize(ctx gas.Context, c *call) error {
	d, err := m.decide(ctx, c)
	if err != nil {
		return err
	}
	if err = d.err(c); err != nil {
		return err
	}
	c.authorized = true
	return nil
}

// decision is the outcome of evaluating a call's identity policies.
type decision struct {
	action   string
	resource string
	result   policy.Decision
	// orphaned is set for a session whose role is gone, which nothing,
	// a trust policy included, may allow.
	orphaned bool
}

// err is the AccessDenied of a decision that does not allow the call, in the
// form of AWS's messages.
func (d decision) err(c *call) error {
	switch d.result {
	case policy.Allow:
		return nil
	case policy.ExplicitDeny:
		return queryapi.ErrExplicitlyDenied(c.caller.ARN, d.action, d.resource)
	default:
		return queryapi.ErrNotAllowed(c.caller.ARN, d.action, d.resource)
	}
}

// decide evaluates the call by its entry in operations: Allow for the root
// user and an operation every principal may call, else the decision of the
// caller's identity policies for the action on the resource.
func (m *Module) decide(ctx gas.Context, c *call) (decision, error) {
	op, ok := operations[c.svc][c.op]
	if !ok {
		return decision{}, fmt.Errorf("query: %s has no authorization entry", c.op)
	}
	if op.always || c.signer.Root {
		return decision{action: op.action, result: policy.Allow}, nil
	}
	resource, err := op.resource(m, ctx, c)
	if err != nil {
		return decision{}, err
	}
	if c.caller.Orphaned {
		// A session whose role is gone may do nothing but
		// GetCallerIdentity. AWS documents no answer for one; its role,
		// and any trust in it, is bound to an ID no role has now.
		return decision{
			action: op.action, resource: resource,
			result: policy.ImplicitDeny, orphaned: true,
		}, nil
	}
	keys := globalKeys(ctx, c)
	if op.context != nil {
		for k, v := range op.context(c) {
			keys[k] = v
		}
	}
	if err = m.addTagKeys(ctx, c, resource, keys); err != nil {
		return decision{}, err
	}
	unknown := m.addOrgKeys(ctx, c, keys)
	res, err := evaluate(c, op.action, resource, keys, unknown)
	if err != nil {
		return decision{}, err
	}
	return decision{action: op.action, resource: resource, result: res}, nil
}

// evaluate evaluates the caller's identity policies for the action on the
// resource. Every source of policies, inline and managed, a user's and a
// session's role's, reaches it the same way: as documents on the verified
// principal, which the store's SigningKey supplies.
func evaluate(
	c *call,
	action, resource string,
	keys map[string][]string,
	unknown []string,
) (policy.Decision, error) {
	policies := make([]*policy.Policy, 0, len(c.signer.Policies))
	for i, doc := range c.signer.Policies {
		p, err := parseDocument(string(doc), identityDocument)
		if err != nil {
			// Every document was parsed when it was stored.
			return policy.ImplicitDeny,
				fmt.Errorf("query: parse policy %d of %s: %w", i, c.caller.ARN, err)
		}
		policies = append(policies, p)
	}
	res := policy.Evaluate(policy.Request{
		Action:    action,
		Resource:  resource,
		Principal: c.caller.ARN,
		Context:   keys,
		Unknown:   unknown,
	}, policies...)
	return res.Decision, nil
}

// globalKeys are the global condition keys this service can supply for the
// call (the IAM User Guide, AWS global condition context keys), which also
// fill the policy variables.
func globalKeys(ctx gas.Context, c *call) map[string][]string {
	r := ctx.Request()
	now := time.Now().UTC()
	keys := map[string][]string{
		"aws:PrincipalAccount": {c.caller.AccountID},
		"aws:userid":           {c.caller.UserID},
		"aws:CurrentTime":      {now.Format(time.RFC3339)},
		"aws:EpochTime":        {strconv.FormatInt(now.Unix(), 10)},
		"aws:SecureTransport":  {strconv.FormatBool(r.TLS != nil)},
		"aws:RequestedRegion":  {requestedRegion},
	}
	if arn := c.caller.PrincipalARN(); arn != "" {
		keys["aws:PrincipalArn"] = []string{arn}
	}
	switch c.caller.Kind {
	case contracts.PrincipalUser:
		keys["aws:username"] = []string{c.caller.UserName}
		keys["aws:PrincipalType"] = []string{"User"}
	case contracts.PrincipalRoleSession:
		keys["aws:PrincipalType"] = []string{"AssumedRole"}
	case contracts.PrincipalRoot:
		keys["aws:PrincipalType"] = []string{"Account"}
	}
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		keys["aws:SourceIp"] = []string{host}
	}
	return keys
}

// orgKeyNames are the organization keys, which are unknown together.
var orgKeyNames = []string{"aws:PrincipalOrgID", "aws:PrincipalOrgPaths"}

// addOrgKeys adds the caller's organization keys to keys:
// aws:PrincipalOrgID and aws:PrincipalOrgPaths for a caller whose account
// is an ACTIVE member of the organization, or its management account, and
// neither for any other (the IAM User Guide, AWS global condition context
// keys: "only if the principal is a member of an organization", "also
// applies to the management account"). When the accounts service cannot be
// asked, it returns both keys' names, for the evaluation to take as
// unknown, so that a condition on them fails closed; the failure is logged
// once for the call.
func (m *Module) addOrgKeys(ctx gas.Context, c *call, keys map[string][]string) []string {
	if c.org == nil {
		k, err := m.orgs.For(ctx, c.caller.AccountID)
		if err != nil {
			httpx.Logger(ctx).Warn("the organization keys are unknown").
				Str("account", c.caller.AccountID).Err("error", err).Send()
		}
		c.org = &k
	}
	if c.org.Unknown {
		return orgKeyNames
	}
	if c.org.OrgID != "" {
		keys["aws:PrincipalOrgID"] = []string{c.org.OrgID}
		keys["aws:PrincipalOrgPaths"] = c.org.Paths
	}
	return nil
}

// requestedRegion is the aws:RequestedRegion of every call, whatever region
// its credential is scoped to: IAM has one endpoint, in us-east-1, so "IAM
// calls are always made to the us-east-1 Region" (the IAM User Guide, AWS
// global condition context keys), and requests to the STS global endpoint
// "have a value of us-east-1 for the aws:RequestedRegion condition key"
// (the IAM User Guide, AWS STS Regions and endpoints). Identity serves both
// from one endpoint, as IAM's and the STS global endpoint.
const requestedRegion = "us-east-1"

// addTagKeys adds the tag condition keys the reference lists for the
// resource types and the caller: aws:ResourceTag/<key> for a user, role or
// managed policy the request acts on, with iam:ResourceTag/<key> for a user
// or role, from its stored tags; and aws:PrincipalTag/<key> from the
// caller's tags, a user's own or a session's role's.
func (m *Module) addTagKeys(
	ctx gas.Context,
	c *call,
	resource string,
	keys map[string][]string,
) error {
	tags, iamKeys, err := m.resourceTags(ctx, resource)
	if err != nil {
		return err
	}
	for _, t := range tags {
		keys["aws:ResourceTag/"+t.Key] = []string{t.Value}
		if iamKeys {
			keys["iam:ResourceTag/"+t.Key] = []string{t.Value}
		}
	}
	if tags, err = m.principalTags(ctx, c.caller); err != nil {
		return err
	}
	for _, t := range tags {
		keys["aws:PrincipalTag/"+t.Key] = []string{t.Value}
	}
	return nil
}

// resourceTags returns the tags of the user, role or managed policy the ARN
// names, and whether it is a user or role, which iam:ResourceTag covers.
// An ARN of anything else, or of nothing that exists, has none.
func (m *Module) resourceTags(ctx gas.Context, arn string) ([]contracts.Tag, bool, error) {
	if account, path, name, ok := contracts.ParseUserARN(arn); ok {
		tags, err := m.userTags(ctx, account, path, name)
		return tags, true, err
	}
	if account, path, name, ok := contracts.ParseRoleARN(arn); ok {
		tags, err := m.roleTags(ctx, account, path, name)
		return tags, true, err
	}
	if account, _, _, ok := contracts.ParsePolicyARN(arn); ok {
		p, err := m.store.GetPolicy(ctx, account, arn)
		switch {
		case errors.Is(err, contracts.ErrPolicyNotFound):
			return nil, false, nil
		case err != nil:
			return nil, false, err
		}
		return p.Tags, false, nil
	}
	return nil, false, nil
}

// userTags returns the tags of the user with the path and name, or none.
func (m *Module) userTags(ctx gas.Context, account, path, name string) ([]contracts.Tag, error) {
	u, err := m.store.GetUser(ctx, account, name)
	switch {
	case errors.Is(err, contracts.ErrUserNotFound):
		return nil, nil
	case err != nil:
		return nil, err
	case u.Path != path:
		return nil, nil
	}
	return u.Tags, nil
}

// roleTags returns the tags of the role with the path and name, or none.
func (m *Module) roleTags(ctx gas.Context, account, path, name string) ([]contracts.Tag, error) {
	r, err := m.store.GetRole(ctx, account, name)
	switch {
	case errors.Is(err, contracts.ErrRoleNotFound):
		return nil, nil
	case err != nil:
		return nil, err
	case r.Path != path:
		return nil, nil
	}
	return r.Tags, nil
}

// principalTags returns the caller's tags: an IAM user's, or a role
// session's role's, while the role is the one the session was created for.
func (m *Module) principalTags(ctx gas.Context, p *contracts.Principal) ([]contracts.Tag, error) {
	switch {
	case p.Kind == contracts.PrincipalUser:
		u, err := m.store.GetUser(ctx, p.AccountID, p.UserName)
		if errors.Is(err, contracts.ErrUserNotFound) {
			return nil, nil
		}
		if err != nil {
			return nil, err
		}
		return u.Tags, nil
	case p.Kind == contracts.PrincipalRoleSession && !p.Orphaned:
		_, _, name, _ := contracts.ParseRoleARN(p.RoleARN)
		r, err := m.store.GetRole(ctx, p.AccountID, name)
		if errors.Is(err, contracts.ErrRoleNotFound) {
			return nil, nil
		}
		if err != nil {
			return nil, err
		}
		if r.ID != callerID(p) {
			return nil, nil
		}
		return r.Tags, nil
	}
	return nil, nil
}

// callerID is the unique ID a trust binding must have to name the caller: a
// user's ID, or a role session's role's. Other callers match no binding.
func callerID(p *contracts.Principal) string {
	switch p.Kind {
	case contracts.PrincipalUser:
		return p.UserID
	case contracts.PrincipalRoleSession:
		id, _, _ := strings.Cut(p.UserID, ":")
		return id
	default:
		return ""
	}
}
