package query

import (
	"errors"
	"net/http"
	"regexp"
	"time"

	"github.com/gasmod/gas"

	"tule.dev/identity/internal/contracts"
	"tule.dev/identity/internal/httpx"
	"tule.dev/identity/internal/queryapi"
)

func (m *Module) getCallerIdentity(ctx gas.Context, c *call) error {
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

// organizationRoleARN matches the ARN of the one role a principal can
// assume, capturing its account.
var organizationRoleARN = regexp.MustCompile(
	`^arn:aws:iam::(\d{12}):role/` + contracts.OrganizationRoleName + `$`)

// The AssumeRole parameters that would narrow the session's permissions.
// With no policies to narrow, a session would get more than they ask for, so
// a request that sets one is refused.
var sessionPolicyParams = []string{"Policy", "PolicyArns."}

func (m *Module) assumeRole(ctx gas.Context, c *call) error {
	roleARN, err := queryapi.RoleARN.Required(c.params, "RoleArn")
	if err != nil {
		return err
	}
	session, err := queryapi.RoleSessionName.Required(c.params, "RoleSessionName")
	if err != nil {
		return err
	}
	duration, set, err := queryapi.Int(c.params, "DurationSeconds",
		contracts.MinSessionDuration, contracts.MaxSessionDuration)
	if err != nil {
		return err
	}
	if !set {
		duration = contracts.DefaultSessionDuration
	}
	if duration > contracts.RoleMaxSessionDuration {
		return queryapi.ErrValidation(
			"The requested DurationSeconds exceeds the MaxSessionDuration set for this role.")
	}
	for _, prefix := range sessionPolicyParams {
		if c.params.HasPrefix(prefix) {
			return queryapi.ErrInvalidParameterValue(
				"This service does not support session policies.")
		}
	}

	account, err := m.assumableAccount(ctx, c.caller, roleARN)
	if err != nil {
		return err
	}
	rs, err := m.store.CreateRoleSession(ctx, contracts.CreateRoleSessionInput{
		AccountID:   account,
		SessionName: session,
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

// assumableAccount returns the account of the role roleARN names, when the
// caller may assume it: the caller is the management account's root user,
// and the role is OrganizationAccountAccessRole in an active member account
// other than the management account, which Organizations creates no such
// role in. The accounts service says which account manages the
// organization, and the root user's must be it. Every other request is
// refused with AccessDenied, as AWS refuses a role that does not exist and
// one the caller may not assume alike.
func (m *Module) assumableAccount(
	ctx gas.Context,
	caller *contracts.Principal,
	roleARN string,
) (string, error) {
	denied := queryapi.ErrAccessDenied(caller.ARN, "sts:AssumeRole", roleARN)
	if caller.Kind != contracts.PrincipalRoot {
		return "", denied
	}
	match := organizationRoleARN.FindStringSubmatch(roleARN)
	if match == nil {
		return "", denied
	}
	account := match[1]

	management, err := m.accounts.ManagementAccountID(ctx)
	switch {
	case errors.Is(err, contracts.ErrAccountNotFound),
		errors.Is(err, contracts.ErrNoAccountDirectory):
		return "", denied
	case err != nil:
		return "", err
	case management != caller.AccountID:
		return "", errManagementMismatch(ctx, management, caller.AccountID)
	case account == management:
		return "", denied
	}

	active, err := m.accounts.IsActiveMember(ctx, account)
	switch {
	case errors.Is(err, contracts.ErrAccountNotFound):
		return "", denied
	case err != nil:
		return "", err
	case !active:
		return "", denied
	}
	return account, nil
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
