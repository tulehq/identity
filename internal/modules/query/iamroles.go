package query

import (
	"errors"

	"github.com/gasmod/gas"

	"tule.dev/identity/internal/contracts"
	"tule.dev/identity/internal/queryapi"
)

// errNoSuchRole is the NoSuchEntity of a role name no role has.
func errNoSuchRole(name string) *queryapi.Error {
	return queryapi.ErrNoSuchEntity("The role with name " + name + " cannot be found.")
}

// roleError maps the store's role sentinels to the error documents that name
// the role.
func roleError(err error, name string) error {
	switch {
	case errors.Is(err, contracts.ErrRoleNotFound):
		return errNoSuchRole(name)
	case errors.Is(err, contracts.ErrRoleExists):
		return queryapi.ErrEntityAlreadyExists("Role with name " + name + " already exists.")
	}
	var ip *contracts.InvalidPrincipalError
	if errors.As(err, &ip) {
		return queryapi.ErrMalformedPolicy(`Invalid principal in policy: "AWS":"` + ip.ARN + `"`)
	}
	return err
}

// trustPolicy reads a role's trust policy from field, with the user and role
// ARNs it names, which the store binds to their unique IDs.
func trustPolicy(c *call, field string) (doc string, principals []string, err error) {
	if doc, err = policyDocument(c, field, trustDocument, contracts.MaxRoleTrustPolicySize,
		"ACLSizePerRole"); err != nil {
		return "", nil, err
	}
	principals, err = bindablePrincipals(doc)
	return doc, principals, err
}

// wireRole is a role on the wire, its trust policy as shownTrust shows it;
// tags are reported when full and the role has some.
func wireRole(r *contracts.Role, full bool) (queryapi.Role, error) {
	trust, err := shownTrust(r)
	if err != nil {
		return queryapi.Role{}, err
	}
	out := queryapi.Role{
		Path:                     r.Path,
		RoleName:                 r.Name,
		RoleID:                   r.ID,
		Arn:                      r.ARN,
		CreateDate:               queryapi.Stamp(r.CreateDate),
		AssumeRolePolicyDocument: queryapi.EncodeDocument(trust),
		Description:              r.Description,
		MaxSessionDuration:       r.MaxSessionDuration,
	}
	if full && len(r.Tags) > 0 {
		tags := queryapi.ListOf(wireTags(r.Tags))
		out.Tags = &tags
	}
	return out, nil
}

// maxSessionDuration reads the optional MaxSessionDuration, unset when the
// request sets none.
func maxSessionDuration(c *call, unset int) (int, error) {
	n, set, err := queryapi.Int(c.params, "MaxSessionDuration",
		queryapi.MinRoleMaxSessionDuration, queryapi.MaxRoleMaxSessionDuration)
	if !set {
		n = unset
	}
	return n, err
}

// createRoleInput reads the CreateRole parameters.
func createRoleInput(c *call) (in contracts.CreateRoleInput, err error) {
	in.AccountID = c.caller.AccountID
	if in.Name, err = queryapi.RoleName.Required(c.params, "RoleName"); err != nil {
		return in, err
	}
	if in.Path, err = pathParam(c, queryapi.Path, "Path"); err != nil {
		return in, err
	}
	if in.TrustPolicy, in.TrustPrincipals, err = trustPolicy(c,
		"AssumeRolePolicyDocument"); err != nil {
		return in, err
	}
	if in.Description, err = queryapi.RoleDescription.Optional(c.params,
		"Description"); err != nil {
		return in, err
	}
	if in.MaxSessionDuration, err = maxSessionDuration(c,
		contracts.RoleMaxSessionDuration); err != nil {
		return in, err
	}
	if in.Tags, _, err = queryapi.Tags(c.params, "Tags"); err != nil {
		return in, err
	}
	// A permissions boundary is refused rather than answered as though it
	// were kept: boundaries are not evaluated.
	if c.params.HasPrefix("PermissionsBoundary") {
		return in, queryapi.ErrInvalidInput(
			"This service does not support PermissionsBoundary on roles.")
	}
	return in, nil
}

func (m *Module) createRole(ctx gas.Context, c *call) error {
	in, err := createRoleInput(c)
	if err != nil {
		return err
	}
	if err = m.authorize(ctx, c); err != nil {
		return err
	}

	r, err := m.store.CreateRole(ctx, in)
	if err != nil {
		return roleError(err, in.Name)
	}
	wire, err := wireRole(r, true)
	if err != nil {
		return err
	}
	return write(ctx, c, queryapi.RoleResult{Role: wire})
}

func (m *Module) getRole(ctx gas.Context, c *call) error {
	name, err := queryapi.RoleName.Required(c.params, "RoleName")
	if err != nil {
		return err
	}
	if err = m.authorize(ctx, c); err != nil {
		return err
	}

	r, err := m.store.GetRole(ctx, c.caller.AccountID, name)
	if err != nil {
		return roleError(err, name)
	}
	wire, err := wireRole(r, true)
	if err != nil {
		return err
	}
	return write(ctx, c, queryapi.RoleResult{Role: wire})
}

func (m *Module) listRoles(ctx gas.Context, c *call) error {
	prefix, err := pathParam(c, queryapi.PathPrefix, "PathPrefix")
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

	page, err := m.store.ListRoles(ctx, contracts.ListRolesInput{
		AccountID:  c.caller.AccountID,
		PathPrefix: prefix,
		Marker:     marker,
		MaxItems:   maxItems,
	})
	if err != nil {
		return err
	}
	roles := make([]queryapi.Role, 0, len(page.Items))
	for i := range page.Items {
		wire, wErr := wireRole(&page.Items[i], false)
		if wErr != nil {
			return wErr
		}
		roles = append(roles, wire)
	}
	return write(ctx, c, queryapi.ListRolesResult{
		Roles:       queryapi.ListOf(roles),
		IsTruncated: page.Marker != "",
		Marker:      page.Marker,
	})
}

func (m *Module) updateRole(ctx gas.Context, c *call) error {
	name, err := queryapi.RoleName.Required(c.params, "RoleName")
	if err != nil {
		return err
	}
	in := contracts.UpdateRoleInput{AccountID: c.caller.AccountID, Name: name}
	if _, set := c.params.Get("Description"); set {
		d, dErr := queryapi.RoleDescription.Optional(c.params, "Description")
		if dErr != nil {
			return dErr
		}
		in.Description = &d
	}
	if in.MaxSessionDuration, err = maxSessionDuration(c, 0); err != nil {
		return err
	}
	if err = m.authorize(ctx, c); err != nil {
		return err
	}

	if err = m.store.UpdateRole(ctx, in); err != nil {
		return roleError(err, name)
	}
	return write(ctx, c, queryapi.EmptyResult{})
}

func (m *Module) updateAssumeRolePolicy(ctx gas.Context, c *call) error {
	name, err := queryapi.RoleName.Required(c.params, "RoleName")
	if err != nil {
		return err
	}
	trust, principals, err := trustPolicy(c, "PolicyDocument")
	if err != nil {
		return err
	}
	if err = m.authorize(ctx, c); err != nil {
		return err
	}

	if err = m.store.UpdateAssumeRolePolicy(ctx, c.caller.AccountID, name, trust,
		principals); err != nil {
		return roleError(err, name)
	}
	return write(ctx, c, nil)
}

func (m *Module) deleteRole(ctx gas.Context, c *call) error {
	name, err := queryapi.RoleName.Required(c.params, "RoleName")
	if err != nil {
		return err
	}
	if err = m.authorize(ctx, c); err != nil {
		return err
	}

	if err = m.store.DeleteRole(ctx, c.caller.AccountID, name); err != nil {
		return roleError(err, name)
	}
	return write(ctx, c, nil)
}
