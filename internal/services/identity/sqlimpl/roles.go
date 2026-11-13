package sqlimpl

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"tule.dev/identity/internal/contracts"
)

const roleColumns = `id, account_id, name, path, trust_policy, description,
	max_session_duration, created_at FROM roles`

func scanRole(r scanner) (cursored[contracts.Role], error) {
	var (
		created int64
		role    contracts.Role
	)
	err := r.Scan(&role.ID, &role.AccountID, &role.Name, &role.Path, &role.TrustPolicy,
		&role.Description, &role.MaxSessionDuration, &created)
	role.CreateDate = unstamp(created)
	role.ARN = contracts.RoleARN(role.AccountID, role.Path, role.Name)
	return cursored[contracts.Role]{item: role, cursor: role.Name}, err
}

// loadRole reads the role of the account with the name, compared without
// regard to case, with its trust bindings, failing with
// contracts.ErrRoleNotFound when there is none.
func loadRole(ctx context.Context, tx *sql.Tx, accountID, name string) (*contracts.Role, error) {
	c, err := scanRole(tx.QueryRowContext(ctx,
		`SELECT `+roleColumns+` WHERE account_id = ? AND name = ? COLLATE NOCASE`,
		accountID, name))
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return nil, contracts.ErrRoleNotFound
	case err != nil:
		return nil, fmt.Errorf("read role: %w", err)
	}
	if c.item.TrustBindings, err = loadBindings(ctx, tx, c.item.ID); err != nil {
		return nil, err
	}
	return &c.item, nil
}

// loadBindings reads the role's trust bindings in order of their ARNs, each
// Current while a user or role has its ID.
func loadBindings(
	ctx context.Context,
	tx *sql.Tx,
	roleID string,
) ([]contracts.TrustBinding, error) {
	return queryAll(ctx, tx, func(r scanner) (contracts.TrustBinding, error) {
		var b contracts.TrustBinding
		return b, r.Scan(&b.ARN, &b.PrincipalID, &b.Current)
	},
		`SELECT t.arn, t.principal_id,
		        EXISTS (SELECT 1 FROM users u WHERE u.id = t.principal_id) OR
		        EXISTS (SELECT 1 FROM roles r WHERE r.id = t.principal_id)
		 FROM trust_principals t WHERE t.role_id = ? ORDER BY t.arn`, roleID)
}

// bindPrincipals replaces the role's trust bindings with those of the ARNs,
// each bound to the unique ID of the user or role that has it now, its path
// and name compared with their case, as a Principal's are. An ARN no user
// or role has is a *contracts.InvalidPrincipalError.
func bindPrincipals(ctx context.Context, tx *sql.Tx, roleID string, arns []string) error {
	if err := exec(ctx, tx, `DELETE FROM trust_principals WHERE role_id = ?`, roleID); err != nil {
		return err
	}
	for _, arn := range arns {
		id, err := resolvePrincipal(ctx, tx, arn)
		if err != nil {
			return err
		}
		if err = exec(ctx, tx,
			`INSERT INTO trust_principals (role_id, arn, principal_id) VALUES (?, ?, ?)
			 ON CONFLICT (role_id, arn) DO NOTHING`, roleID, arn, id); err != nil {
			return err
		}
	}
	return nil
}

// resolvePrincipal returns the unique ID of the user or role with the ARN.
func resolvePrincipal(ctx context.Context, tx *sql.Tx, arn string) (string, error) {
	table := "users"
	account, path, name, ok := contracts.ParseUserARN(arn)
	if !ok {
		table = "roles"
		if account, path, name, ok = contracts.ParseRoleARN(arn); !ok {
			return "", fmt.Errorf("resolve principal: %s is not a user or role ARN", arn)
		}
	}
	var id string
	err := tx.QueryRowContext(ctx,
		`SELECT id FROM `+table+` WHERE account_id = ? AND path = ? AND name = ? COLLATE BINARY`,
		account, path, name).Scan(&id)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return "", &contracts.InvalidPrincipalError{ARN: arn}
	case err != nil:
		return "", fmt.Errorf("resolve principal: %w", err)
	}
	return id, nil
}

// CreateRole creates a role in the account with the tags, failing with
// contracts.ErrRoleExists when one has the name already, compared without
// regard to case.
func (s *Service) CreateRole(
	ctx context.Context,
	in contracts.CreateRoleInput,
) (*contracts.Role, error) {
	var out *contracts.Role
	err := s.inTx(ctx, func(tx *sql.Tx) error {
		var cErr error
		out, cErr = s.createRole(ctx, tx, in)
		return cErr
	})
	return out, err
}

func (s *Service) createRole(
	ctx context.Context,
	tx *sql.Tx,
	in contracts.CreateRoleInput,
) (*contracts.Role, error) {
	taken, err := exists(ctx, tx,
		`SELECT 1 FROM roles WHERE account_id = ? AND name = ? COLLATE NOCASE LIMIT 1`,
		in.AccountID, in.Name)
	if err != nil {
		return nil, err
	}
	if taken {
		return nil, contracts.ErrRoleExists
	}
	id, err := s.unusedID(ctx, tx, newRoleID, `SELECT 1 FROM roles WHERE id = ? LIMIT 1`)
	if err != nil {
		return nil, err
	}
	r := contracts.Role{
		CreateDate:         unstamp(stamp(s.now())),
		AccountID:          in.AccountID,
		ID:                 id,
		Name:               in.Name,
		Path:               in.Path,
		ARN:                contracts.RoleARN(in.AccountID, in.Path, in.Name),
		TrustPolicy:        in.TrustPolicy,
		Description:        in.Description,
		Tags:               in.Tags,
		MaxSessionDuration: in.MaxSessionDuration,
	}
	if err = exec(ctx, tx,
		`INSERT INTO roles (id, account_id, name, path, trust_policy, description,
		                    max_session_duration, created_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		r.ID, r.AccountID, r.Name, r.Path, r.TrustPolicy, r.Description,
		r.MaxSessionDuration, stamp(r.CreateDate)); err != nil {
		return nil, err
	}
	if err = putTagsOn(ctx, tx, roleTags, r.ID, in.Tags); err != nil {
		return nil, err
	}
	if err = bindPrincipals(ctx, tx, r.ID, in.TrustPrincipals); err != nil {
		return nil, err
	}
	if r.TrustBindings, err = loadBindings(ctx, tx, r.ID); err != nil {
		return nil, err
	}
	return &r, nil
}

// GetRole returns the role of the account with the name, with its tags.
func (s *Service) GetRole(ctx context.Context, accountID, name string) (*contracts.Role, error) {
	var out *contracts.Role
	err := s.inTx(ctx, func(tx *sql.Tx) error {
		r, err := loadRole(ctx, tx, accountID, name)
		if err != nil {
			return err
		}
		if r.Tags, err = tagsOf(ctx, tx, roleTags, r.ID); err != nil {
			return err
		}
		out = r
		return nil
	})
	return out, err
}

// ListRoles lists the roles of the account whose path starts with the
// prefix, in order of their names without regard to case.
func (s *Service) ListRoles(
	ctx context.Context,
	in contracts.ListRolesInput,
) (*contracts.Page[contracts.Role], error) {
	var out *contracts.Page[contracts.Role]
	err := s.inTx(ctx, func(tx *sql.Tx) error {
		after, err := decodeMarker(in.Marker, in.AccountID, listRoles, in.PathPrefix)
		if err != nil {
			return err
		}
		rows, err := queryAll(ctx, tx, scanRole,
			`SELECT `+roleColumns+`
			 WHERE account_id = ? AND substr(path, 1, length(?)) = ?
			   AND (? = '' OR name > ? COLLATE NOCASE)
			 ORDER BY name COLLATE NOCASE LIMIT ?`,
			in.AccountID, in.PathPrefix, in.PathPrefix, after, after, in.MaxItems+1)
		if err != nil {
			return err
		}
		for i := range rows {
			if rows[i].item.TrustBindings, err = loadBindings(
				ctx,
				tx,
				rows[i].item.ID,
			); err != nil {
				return err
			}
		}
		out = paginate(rows, in.MaxItems, in.AccountID, listRoles, in.PathPrefix)
		return nil
	})
	return out, err
}

// AllRoles returns every role of every account, in order of account and
// name, without trust bindings or tags.
func (s *Service) AllRoles(ctx context.Context) ([]contracts.Role, error) {
	var out []contracts.Role
	err := s.inTx(ctx, func(tx *sql.Tx) error {
		rows, err := queryAll(ctx, tx, scanRole,
			`SELECT `+roleColumns+` ORDER BY account_id, name COLLATE NOCASE`)
		if err != nil {
			return err
		}
		out = make([]contracts.Role, len(rows))
		for i := range rows {
			out[i] = rows[i].item
		}
		return nil
	})
	return out, err
}

// UpdateRole sets the role's description and maximum session duration, each
// when the input sets it.
func (s *Service) UpdateRole(ctx context.Context, in contracts.UpdateRoleInput) error {
	return s.inTx(ctx, func(tx *sql.Tx) error {
		r, err := loadRole(ctx, tx, in.AccountID, in.Name)
		if err != nil {
			return err
		}
		if in.Description != nil {
			r.Description = *in.Description
		}
		if in.MaxSessionDuration != 0 {
			r.MaxSessionDuration = in.MaxSessionDuration
		}
		return exec(ctx, tx,
			`UPDATE roles SET description = ?, max_session_duration = ? WHERE id = ?`,
			r.Description, r.MaxSessionDuration, r.ID)
	})
}

// UpdateAssumeRolePolicy replaces the role's trust policy and its bindings.
func (s *Service) UpdateAssumeRolePolicy(
	ctx context.Context,
	accountID, name, document string,
	principals []string,
) error {
	return s.inTx(ctx, func(tx *sql.Tx) error {
		r, err := loadRole(ctx, tx, accountID, name)
		if err != nil {
			return err
		}
		if err = bindPrincipals(ctx, tx, r.ID, principals); err != nil {
			return err
		}
		return exec(ctx, tx, `UPDATE roles SET trust_policy = ? WHERE id = ?`, document, r.ID)
	})
}

// DeleteRole deletes the role with its tags. Its sessions remain until they
// expire, with no role to take permissions from.
func (s *Service) DeleteRole(ctx context.Context, accountID, name string) error {
	return s.inTx(ctx, func(tx *sql.Tx) error {
		r, err := loadRole(ctx, tx, accountID, name)
		if err != nil {
			return err
		}
		if err = checkNoPolicies(ctx, tx, contracts.EntityRole, r.ID); err != nil {
			return err
		}
		for _, q := range []string{
			`DELETE FROM role_tags WHERE role_id = ?`,
			`DELETE FROM trust_principals WHERE role_id = ?`,
			`DELETE FROM roles WHERE id = ?`,
		} {
			if err = exec(ctx, tx, q, r.ID); err != nil {
				return err
			}
		}
		return nil
	})
}

// OrganizationRoleCreated reports whether contracts.OrganizationRoleName has
// been created in the account.
func (s *Service) OrganizationRoleCreated(ctx context.Context, accountID string) (bool, error) {
	var out bool
	err := s.inTx(ctx, func(tx *sql.Tx) error {
		var eErr error
		out, eErr = exists(ctx, tx,
			`SELECT 1 FROM organization_roles WHERE account_id = ? LIMIT 1`, accountID)
		return eErr
	})
	return out, err
}

// CreateOrganizationRole creates contracts.OrganizationRoleName in the
// account, once: with the default path and maximum session duration, a
// trust policy for the management account, and AdministratorAccess
// attached. It records the creation, so a role the account deletes is never
// created again: after the first time it fails with
// contracts.ErrOrganizationRoleCreated.
func (s *Service) CreateOrganizationRole(
	ctx context.Context,
	accountID, managementAccountID string,
) (*contracts.Role, error) {
	var out *contracts.Role
	err := s.inTx(ctx, func(tx *sql.Tx) error {
		created, err := exists(ctx, tx,
			`SELECT 1 FROM organization_roles WHERE account_id = ? LIMIT 1`, accountID)
		if err != nil {
			return err
		}
		if created {
			return contracts.ErrOrganizationRoleCreated
		}
		r, err := s.createRole(ctx, tx, contracts.CreateRoleInput{
			AccountID:          accountID,
			Name:               contracts.OrganizationRoleName,
			Path:               "/",
			TrustPolicy:        contracts.OrganizationTrustPolicy(managementAccountID),
			MaxSessionDuration: contracts.RoleMaxSessionDuration,
		})
		if err != nil {
			return err
		}
		admin, err := loadPolicy(ctx, tx, accountID, contracts.AdministratorAccessARN)
		if err != nil {
			return fmt.Errorf("read AdministratorAccess: %w", err)
		}
		if err = exec(ctx, tx,
			`INSERT INTO attached_policies (entity_kind, entity_id, account_id, policy_id)
			 VALUES (?, ?, ?, ?)`, contracts.EntityRole, r.ID, accountID, admin.ID); err != nil {
			return err
		}
		if err = exec(ctx, tx,
			`INSERT INTO organization_roles (account_id, created_at) VALUES (?, ?)`,
			accountID, stamp(s.now())); err != nil {
			return err
		}
		out = r
		return nil
	})
	return out, err
}
