package query

import (
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/gasmod/gas"
	"tule.dev/policy"

	"tule.dev/identity/internal/contracts"
	"tule.dev/identity/internal/httpx"
	"tule.dev/identity/internal/queryapi"
	"tule.dev/identity/internal/trustdoc"
)

func (m *Module) getCallerIdentity(ctx gas.Context, c *call) error {
	if err := m.authorize(ctx, c); err != nil {
		return err
	}
	return write(ctx, c, queryapi.GetCallerIdentityResult{
		UserID:  c.caller.UserID,
		Account: c.caller.AccountID,
		Arn:     c.caller.ARN,
	})
}

func (m *Module) getAccessKeyInfo(ctx gas.Context, c *call) error {
	keyID, err := queryapi.AccessKeyID.Required(c.params, "AccessKeyId")
	if err != nil {
		return err
	}
	if err = m.authorize(ctx, c); err != nil {
		return err
	}

	p, err := m.store.Principal(ctx, keyID)
	if errors.Is(err, contracts.ErrAccessKeyNotFound) {
		return queryapi.ErrInvalidParameterValue("The access key ID " + keyID +
			" does not belong to any account this service knows.")
	}
	if err != nil {
		return err
	}
	return write(ctx, c, queryapi.GetAccessKeyInfoResult{Account: p.AccountID})
}

// The AssumeRole parameters that would narrow the session's permissions.
// Session policies are not evaluated, so a session would get more than they
// ask for, and a request that sets one is refused.
var sessionPolicyParams = []string{"Policy", "PolicyArns."}

func refuseSessionPolicies(c *call) error {
	for _, prefix := range sessionPolicyParams {
		if c.params.HasPrefix(prefix) {
			return queryapi.ErrInvalidParameterValue(
				"This service does not support session policies.")
		}
	}
	return nil
}

// assumeRole creates a session of the role RoleArn names. The caller's own
// identity policies must allow sts:AssumeRole on the role, unless it is the
// root user, and the role's trust policy must allow the caller.
// DurationSeconds is bounded by the role's MaxSessionDuration, and is an
// hour when the request sets none.
// assumeRoleInput is what an AssumeRole asks for.
type assumeRoleInput struct {
	roleARN  string
	session  string
	duration int
}

// assumeRoleParams reads the AssumeRole parameters. DurationSeconds is an
// hour when the request sets none. ExternalId is checked here and read as
// sts:ExternalId by trustKeys.
func assumeRoleParams(c *call) (in assumeRoleInput, err error) {
	if in.roleARN, err = queryapi.RoleARN.Required(c.params, "RoleArn"); err != nil {
		return in, err
	}
	if in.session, err = queryapi.RoleSessionName.Required(c.params,
		"RoleSessionName"); err != nil {
		return in, err
	}
	duration, set, err := queryapi.Int(c.params, "DurationSeconds",
		contracts.MinSessionDuration, contracts.MaxSessionDuration)
	if err != nil {
		return in, err
	}
	in.duration = contracts.DefaultSessionDuration
	if set {
		in.duration = duration
	}
	if _, err = queryapi.ExternalID.Optional(c.params, "ExternalId"); err != nil {
		return in, err
	}
	if err = refuseSessionPolicies(c); err != nil {
		return in, err
	}
	return in, refuseSessionTags(c)
}

// refuseSessionTags refuses session tags, which a session would not carry
// as aws:PrincipalTag, and a source identity, which it would not carry as
// aws:SourceIdentity or keep through role chaining, rather than issue a
// session without what was asked for.
func refuseSessionTags(c *call) error {
	if c.params.HasPrefix("Tags") || c.params.HasPrefix("TransitiveTagKeys") {
		return queryapi.ErrInvalidParameterValue("This service does not support session tags.")
	}
	if _, set := c.params.Get("SourceIdentity"); set {
		return queryapi.ErrInvalidParameterValue(
			"This service does not support SourceIdentity.")
	}
	return nil
}

func (m *Module) assumeRole(ctx gas.Context, c *call) error {
	in, err := assumeRoleParams(c)
	if err != nil {
		return err
	}
	roleARN, duration := in.roleARN, in.duration
	role, err := m.authorizeRole(ctx, c, roleARN, duration)
	if err != nil {
		return err
	}
	if role.ID == "" {
		// Every check has passed against the role as it would be created:
		// create it, then authorize again against the role as stored, which
		// another request may have created first, and changed since.
		if err = m.createOrganizationRole(ctx, role); err != nil {
			return err
		}
		if role, err = m.authorizeRole(ctx, c, roleARN, duration); err != nil {
			return err
		}
		if role.ID == "" {
			return fmt.Errorf("query: %s is still not created", roleARN)
		}
	}
	rs, err := m.store.CreateRoleSession(ctx, contracts.CreateRoleSessionInput{
		Role:        role,
		SessionName: in.session,
		Duration:    time.Duration(duration) * time.Second,
	})
	if err != nil {
		return err
	}
	return write(ctx, c, queryapi.AssumeRoleResult{
		Credentials: queryapi.Credentials{
			AccessKeyID:     rs.AccessKeyID,
			SecretAccessKey: rs.SecretAccessKey,
			SessionToken:    rs.SessionToken,
			Expiration:      queryapi.Stamp(rs.Expiration),
		},
		AssumedRoleUser: queryapi.AssumedRoleUser{
			AssumedRoleID: rs.AssumedRoleID,
			Arn:           rs.ARN,
		},
	})
}

// authorizeAssumeRole authorizes an AssumeRole of the role roleARN names,
// and returns the role. Its trust policy must allow the caller, as a role
// trust policy must "explicitly allow access for principals"; the caller's
// identity policies must not deny sts:AssumeRole on it; and they must allow
// it, unless the caller is the root user or the role is in the caller's
// account and its trust policy allows the caller directly, by its user,
// session or role ARN, or by "*", which TrustMatch reports as Direct, and
// only for a caller of the role's account.
// Within one account, a resource-based
// policy that grants permission directly to the IAM user, the role or the
// session making the request is "not limited by an implicit deny in an
// identity-based policy"; one that grants it to the account is. (The IAM
// User Guide, "How AWS enforcement code logic evaluates requests to allow or
// deny access", Resource-based policies,
// https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_evaluation-logic_policy-eval-denyallow.html.)
// Across accounts both are needed.
func (m *Module) authorizeAssumeRole(
	ctx gas.Context,
	c *call,
	roleARN string,
) (*contracts.Role, error) {
	d, err := m.decide(ctx, c)
	if err != nil {
		return nil, err
	}
	if d.result == policy.ExplicitDeny || d.orphaned {
		return nil, d.err(c)
	}
	role, trust, err := m.assumableRole(ctx, c, roleARN)
	if err != nil {
		return nil, err
	}
	if d.result != policy.Allow && !trust.Direct {
		return nil, d.err(c)
	}
	c.authorized = true
	return role, nil
}

// authorizeRole authorizes the AssumeRole of roleARN for duration seconds,
// and returns the role: a pending OrganizationAccountAccessRole has no ID.
func (m *Module) authorizeRole(
	ctx gas.Context,
	c *call,
	roleARN string,
	duration int,
) (*contracts.Role, error) {
	c.authorized = false
	role, err := m.authorizeAssumeRole(ctx, c, roleARN)
	if err != nil {
		return nil, err
	}
	if duration > role.MaxSessionDuration {
		c.authorized = false
		return nil, queryapi.ErrValidation(
			"The requested DurationSeconds exceeds the MaxSessionDuration set for this role.")
	}
	// "Role chaining limits your ... API role session to a maximum of one
	// hour" (the AssumeRole DurationSeconds reference).
	if c.caller.Kind == contracts.PrincipalRoleSession && duration > chainedSessionDuration {
		c.authorized = false
		return nil, queryapi.ErrValidation("The requested DurationSeconds exceeds the 1 hour " +
			"session limit for roles assumed by role chaining.")
	}
	return role, nil
}

// chainedSessionDuration is the longest session, in seconds, a role session
// may assume a role for.
const chainedSessionDuration = 3600

// createOrganizationRole creates the pending OrganizationAccountAccessRole
// the call was authorized against. One created before, by another request
// or before it was deleted, is not created again.
func (m *Module) createOrganizationRole(ctx gas.Context, pending *contracts.Role) error {
	management, err := m.accounts.ManagementAccountID(ctx)
	if err != nil {
		return fmt.Errorf("query: read the management account: %w", err)
	}
	_, err = m.store.CreateOrganizationRole(ctx, pending.AccountID, management)
	if errors.Is(err, contracts.ErrOrganizationRoleCreated) {
		return nil
	}
	//nolint:wrapcheck // the store's errors are answered as they are
	return err
}

// trustKeys are the condition keys a trust policy is evaluated with.
func trustKeys(ctx gas.Context, c *call) map[string][]string {
	keys := globalKeys(ctx, c)
	keys["sts:RoleSessionName"] = sessionNameKey(c)["sts:RoleSessionName"]
	if v, ok := c.params.Get("ExternalId"); ok {
		keys["sts:ExternalId"] = []string{v}
	}
	return keys
}

// assumableRole returns the role roleARN names, with its trust policy's
// decision, when the trust policy allows the caller to assume it. The role is in the caller's account, or, for a
// caller of the organization's management account, in an active member
// account, where OrganizationAccountAccessRole is created the first time it
// is assumed, as Organizations would have created it, and never again. The accounts service
// says which account manages the organization. Role names are matched with
// their case, as AssumeRole matches them (the IAM User Guide, troubleshooting
// IAM roles). Every refusal is AccessDenied, as AWS refuses a role that does
// not exist and one the caller may not assume alike.
func (m *Module) assumableRole(
	ctx gas.Context,
	c *call,
	roleARN string,
) (*contracts.Role, policy.TrustResult, error) {
	var none policy.TrustResult
	denied := queryapi.ErrAccessDenied(c.caller.ARN, "sts:AssumeRole", roleARN)
	account, path, name, ok := contracts.ParseRoleARN(roleARN)
	if !ok {
		return nil, none, denied
	}
	role, err := m.findRole(ctx, c.caller, account, path, name)
	switch {
	case errors.Is(err, contracts.ErrRoleNotFound), errors.Is(err, errNotAssumable):
		return nil, none, denied
	case err != nil:
		return nil, none, err
	case role.Name != name || role.Path != path:
		return nil, none, denied
	}

	trust, ok, err := trustdoc.Parse(role, callerID(c.caller), httpx.Logger(ctx))
	switch {
	case err != nil:
		return nil, none, err
	case !ok:
		return nil, none, denied
	}
	// The caller is matched by the ARN it signs as alone, a session by its
	// assumed-role ARN, which names its role; and a user or role ARN in the
	// trust policy only while it is bound to the caller's ID. The keys carry
	// aws:PrincipalArn for conditions. An orphaned session is trusted by
	// nothing: its assumed-role ARN still names its old role, which a trust
	// policy naming a new role of that name would match.
	if c.caller.Orphaned {
		return nil, none, denied
	}
	keys := trustKeys(ctx, c)
	res := policy.TrustMatch(trust, role.AccountID, "sts:AssumeRole", c.caller.ARN, keys)
	if res.Decision != policy.Allow {
		return nil, none, denied
	}

	return role, res, nil
}

// findRole returns the role of the account with the name, compared without
// regard to case: a role of the caller's account, or of a member account of
// the organization the caller's account manages, where
// OrganizationAccountAccessRole is created on first need. It returns
// errNotAssumable for an account whose roles the caller cannot reach.
func (m *Module) findRole(
	ctx gas.Context,
	caller *contracts.Principal,
	account, path, name string,
) (*contracts.Role, error) {
	if account == caller.AccountID {
		//nolint:wrapcheck // the store's sentinels are what assumableRole reads
		return m.store.GetRole(ctx, account, name)
	}
	management, err := m.memberAccount(ctx, caller, account)
	if err != nil {
		return nil, err
	}
	if name != contracts.OrganizationRoleName || path != "/" {
		//nolint:wrapcheck // as above
		return m.store.GetRole(ctx, account, name)
	}
	created, err := m.store.OrganizationRoleCreated(ctx, account)
	if err != nil {
		return nil, err
	}
	if created {
		//nolint:wrapcheck // as above
		return m.store.GetRole(ctx, account, name)
	}
	// Not created yet: the request is judged against the role as it would
	// be created, which assumeRole creates only once every check passes.
	return pendingOrganizationRole(account, management), nil
}

// pendingOrganizationRole is OrganizationAccountAccessRole of a member
// account it has not been created in yet, as CreateOrganizationRole would
// create it. It has no ID until it is created.
func pendingOrganizationRole(account, management string) *contracts.Role {
	return &contracts.Role{
		AccountID:          account,
		Name:               contracts.OrganizationRoleName,
		Path:               "/",
		ARN:                contracts.RoleARN(account, "/", contracts.OrganizationRoleName),
		TrustPolicy:        contracts.OrganizationTrustPolicy(management),
		MaxSessionDuration: contracts.RoleMaxSessionDuration,
	}
}

// errNotAssumable is memberAccount's refusal of an account whose roles the
// caller cannot reach.
var errNotAssumable = errors.New("query: the account's roles cannot be assumed by the caller")

// memberAccount checks that account is an active member of the organization
// the caller's account manages, and returns the management account. It
// returns errNotAssumable when it is not, or there is no organization to
// ask about.
func (m *Module) memberAccount(
	ctx gas.Context,
	caller *contracts.Principal,
	account string,
) (string, error) {
	management, err := m.accounts.ManagementAccountID(ctx)
	switch {
	case errors.Is(err, contracts.ErrAccountNotFound),
		errors.Is(err, contracts.ErrNoAccountDirectory):
		return "", errNotAssumable
	case err != nil:
		return "", err
	case management != caller.AccountID && caller.Kind == contracts.PrincipalRoot:
		// The root user is the configured management account's.
		return "", errManagementMismatch(ctx, management, caller.AccountID)
	case management != caller.AccountID:
		return "", errNotAssumable
	}

	active, err := m.accounts.IsActiveMember(ctx, account)
	switch {
	case errors.Is(err, contracts.ErrAccountNotFound):
		return "", errNotAssumable
	case err != nil:
		return "", err
	case !active:
		return "", errNotAssumable
	}
	return management, nil
}

// errManagementMismatch is the failure of an AssumeRole when the accounts
// service's organization is managed by another account than the root
// user's: a misconfiguration, which no AssumeRole can be answered through,
// so it is reported and logged rather than guessed around.
func errManagementMismatch(ctx gas.Context, management, configured string) error {
	httpx.Logger(ctx).Error("the accounts service's management account is not this service's").
		Str("accounts_management_account", management).
		Str("identity_account", configured).Send()
	return queryapi.NewError(http.StatusInternalServerError, queryapi.CodeInternalFailure,
		"The accounts service's organization is managed by account "+management+
			", but the root user here belongs to account "+configured+
			" (TULE_Identity_AccountID). Configure the same management account in both.")
}
