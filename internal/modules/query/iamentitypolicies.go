package query

import (
	"errors"
	"fmt"

	"github.com/gasmod/gas"

	"tule.dev/identity/internal/contracts"
	"tule.dev/identity/internal/queryapi"
)

// The policy operations of users and roles are the same but for the entity
// they name: UserName or RoleName. The attach operations take userNameType
// for a user and the inline ones existingUserNameType, as the IAM model has
// it; a role is roleNameType throughout.

// entityParam reads the user or role an operation names. existing selects
// existingUserNameType for a user.
func entityParam(c *call, kind contracts.EntityKind, existing bool) (contracts.Entity, error) {
	field, rule := "RoleName", queryapi.RoleName
	if kind == contracts.EntityUser {
		field, rule = "UserName", queryapi.UserName
		if existing {
			rule = queryapi.ExistingUserName
		}
	}
	name, err := rule.Required(c.params, field)
	if err != nil {
		return contracts.Entity{}, err
	}
	return contracts.Entity{Kind: kind, AccountID: c.caller.AccountID, Name: name}, nil
}

// entityError maps the store's entity and policy sentinels to the error
// documents that name them.
func entityError(err error, e contracts.Entity, arn, policyName string) error {
	switch {
	case errors.Is(err, contracts.ErrUserNotFound):
		return queryapi.ErrNoSuchUser(e.Name)
	case errors.Is(err, contracts.ErrRoleNotFound):
		return errNoSuchRole(e.Name)
	case errors.Is(err, contracts.ErrInlinePolicyNotFound):
		return queryapi.ErrNoSuchEntity("The " + string(e.Kind) + " policy with name " +
			policyName + " cannot be found.")
	case errors.Is(err, contracts.ErrAttachedPolicyLimitExceeded):
		quota, n := "PoliciesPerUser", contracts.MaxManagedPoliciesPerUser
		if e.Kind == contracts.EntityRole {
			quota, n = "PoliciesPerRole", contracts.MaxManagedPoliciesPerRole
		}
		return queryapi.ErrLimitExceeded(fmt.Sprintf("Cannot exceed quota for %s: %d", quota, n))
	case errors.Is(err, contracts.ErrInlinePolicySizeExceeded):
		n := contracts.MaxUserInlinePolicySize
		if e.Kind == contracts.EntityRole {
			n = contracts.MaxRoleInlinePolicySize
		}
		return queryapi.ErrLimitExceeded(fmt.Sprintf(
			"Maximum policy size of %d bytes exceeded for %s %s", n, e.Kind, e.Name))
	case errors.Is(err, contracts.ErrPolicyNotFound):
		return queryapi.ErrNoSuchEntity("Policy " + arn + " does not exist or is not attachable.")
	}
	return policyError(err, arn, "", "")
}

func (m *Module) attachPolicy(kind contracts.EntityKind) handler {
	return func(ctx gas.Context, c *call) error {
		e, err := entityParam(c, kind, false)
		if err != nil {
			return err
		}
		arn, err := policyARN(c)
		if err != nil {
			return err
		}
		if err = m.authorize(ctx, c); err != nil {
			return err
		}

		if err = m.store.AttachPolicy(ctx, e, arn); err != nil {
			return entityError(err, e, arn, "")
		}
		return write(ctx, c, nil)
	}
}

func (m *Module) detachPolicy(kind contracts.EntityKind) handler {
	return func(ctx gas.Context, c *call) error {
		e, err := entityParam(c, kind, false)
		if err != nil {
			return err
		}
		arn, err := policyARN(c)
		if err != nil {
			return err
		}
		if err = m.authorize(ctx, c); err != nil {
			return err
		}

		if err = m.store.DetachPolicy(ctx, e, arn); err != nil {
			if errors.Is(err, contracts.ErrPolicyNotAttached) {
				return queryapi.ErrNoSuchEntity("Policy " + arn + " was not found.")
			}
			return entityError(err, e, arn, "")
		}
		return write(ctx, c, nil)
	}
}

func (m *Module) listAttachedPolicies(kind contracts.EntityKind) handler {
	return func(ctx gas.Context, c *call) error {
		e, err := entityParam(c, kind, false)
		if err != nil {
			return err
		}
		prefix, err := pathParam(c, queryapi.PolicyPath, "PathPrefix")
		if err != nil {
			return err
		}
		marker, maxItems, err := queryapi.Page(c.params)
		if err != nil {
			return err
		}
		if err = m.authorize(ctx, c); err != nil {
			return err
		}

		page, err := m.store.ListAttachedPolicies(ctx, contracts.ListAttachedPoliciesInput{
			Entity: e, PathPrefix: prefix, Marker: marker, MaxItems: maxItems,
		})
		if err != nil {
			return entityError(err, e, "", "")
		}
		attached := make([]queryapi.AttachedPolicy, 0, len(page.Items))
		for _, p := range page.Items {
			attached = append(
				attached,
				queryapi.AttachedPolicy{PolicyName: p.Name, PolicyArn: p.ARN},
			)
		}
		return write(ctx, c, queryapi.ListAttachedPoliciesResult{
			AttachedPolicies: queryapi.ListOf(attached),
			IsTruncated:      page.Marker != "",
			Marker:           page.Marker,
		})
	}
}

func (m *Module) putInlinePolicy(kind contracts.EntityKind) handler {
	return func(ctx gas.Context, c *call) error {
		e, err := entityParam(c, kind, true)
		if err != nil {
			return err
		}
		name, err := queryapi.PolicyName.Required(c.params, "PolicyName")
		if err != nil {
			return err
		}
		// The aggregate size of the entity's inline policies is the store's
		// to check, with the others in hand.
		doc, err := policyDocument(c, "PolicyDocument", identityDocument, 0, "")
		if err != nil {
			return err
		}
		if err = m.authorize(ctx, c); err != nil {
			return err
		}

		if err = m.store.PutInlinePolicy(ctx, e, name, doc); err != nil {
			return entityError(err, e, "", name)
		}
		return write(ctx, c, nil)
	}
}

func (m *Module) getInlinePolicy(kind contracts.EntityKind) handler {
	return func(ctx gas.Context, c *call) error {
		e, err := entityParam(c, kind, true)
		if err != nil {
			return err
		}
		name, err := queryapi.PolicyName.Required(c.params, "PolicyName")
		if err != nil {
			return err
		}
		if err = m.authorize(ctx, c); err != nil {
			return err
		}

		p, err := m.store.GetInlinePolicy(ctx, e, name)
		if err != nil {
			return entityError(err, e, "", name)
		}
		doc := queryapi.EncodeDocument(p.Document)
		if kind == contracts.EntityRole {
			return write(ctx, c, queryapi.GetRolePolicyResult{
				RoleName: e.Name, PolicyName: p.Name, PolicyDocument: doc,
			})
		}
		return write(ctx, c, queryapi.GetUserPolicyResult{
			UserName: e.Name, PolicyName: p.Name, PolicyDocument: doc,
		})
	}
}

func (m *Module) listInlinePolicies(kind contracts.EntityKind) handler {
	return func(ctx gas.Context, c *call) error {
		e, err := entityParam(c, kind, true)
		if err != nil {
			return err
		}
		marker, maxItems, err := queryapi.Page(c.params)
		if err != nil {
			return err
		}
		if err = m.authorize(ctx, c); err != nil {
			return err
		}

		page, err := m.store.ListInlinePolicies(ctx, contracts.ListInlinePoliciesInput{
			Entity: e, Marker: marker, MaxItems: maxItems,
		})
		if err != nil {
			return entityError(err, e, "", "")
		}
		return write(ctx, c, queryapi.ListInlinePoliciesResult{
			PolicyNames: queryapi.ListOf(page.Items),
			IsTruncated: page.Marker != "",
			Marker:      page.Marker,
		})
	}
}

func (m *Module) deleteInlinePolicy(kind contracts.EntityKind) handler {
	return func(ctx gas.Context, c *call) error {
		e, err := entityParam(c, kind, true)
		if err != nil {
			return err
		}
		name, err := queryapi.PolicyName.Required(c.params, "PolicyName")
		if err != nil {
			return err
		}
		if err = m.authorize(ctx, c); err != nil {
			return err
		}

		if err = m.store.DeleteInlinePolicy(ctx, e, name); err != nil {
			return entityError(err, e, "", name)
		}
		return write(ctx, c, nil)
	}
}
