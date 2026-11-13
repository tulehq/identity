package sqlimpl

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"tule.dev/identity/internal/contracts"
)

// loadEntity reads the ID of the user or role e names, failing with
// contracts.ErrUserNotFound or contracts.ErrRoleNotFound.
func loadEntity(ctx context.Context, tx *sql.Tx, e contracts.Entity) (string, error) {
	switch e.Kind {
	case contracts.EntityUser:
		u, err := loadUser(ctx, tx, e.AccountID, e.Name)
		if err != nil {
			return "", err
		}
		return u.ID, nil
	case contracts.EntityRole:
		r, err := loadRole(ctx, tx, e.AccountID, e.Name)
		if err != nil {
			return "", err
		}
		return r.ID, nil
	default:
		return "", fmt.Errorf("unknown entity kind %q", e.Kind)
	}
}

// checkNoPolicies fails with contracts.ErrHasAttachedPolicies or
// contracts.ErrHasInlinePolicies while the entity has policies, as IAM
// refuses to delete one that does.
func checkNoPolicies(ctx context.Context, tx *sql.Tx, kind contracts.EntityKind, id string) error {
	attached, err := exists(ctx, tx,
		`SELECT 1 FROM attached_policies WHERE entity_kind = ? AND entity_id = ? LIMIT 1`,
		kind, id)
	if err != nil {
		return err
	}
	if attached {
		return contracts.ErrHasAttachedPolicies
	}
	inline, err := exists(ctx, tx,
		`SELECT 1 FROM inline_policies WHERE entity_kind = ? AND entity_id = ? LIMIT 1`,
		kind, id)
	if err != nil {
		return err
	}
	if inline {
		return contracts.ErrHasInlinePolicies
	}
	return nil
}

// maxAttached is how many managed policies an entity of the kind may have
// attached.
func maxAttached(kind contracts.EntityKind) int {
	if kind == contracts.EntityRole {
		return contracts.MaxManagedPoliciesPerRole
	}
	return contracts.MaxManagedPoliciesPerUser
}

// maxInlineSize is the aggregate size of an entity's inline policies.
func maxInlineSize(kind contracts.EntityKind) int {
	if kind == contracts.EntityRole {
		return contracts.MaxRoleInlinePolicySize
	}
	return contracts.MaxUserInlinePolicySize
}

// AttachPolicy attaches the managed policy with the ARN to the entity,
// failing with contracts.ErrAttachedPolicyLimitExceeded when it has its
// quota attached already.
func (s *Service) AttachPolicy(ctx context.Context, e contracts.Entity, arn string) error {
	return s.inTx(ctx, func(tx *sql.Tx) error {
		id, err := loadEntity(ctx, tx, e)
		if err != nil {
			return err
		}
		p, err := loadPolicy(ctx, tx, e.AccountID, arn)
		if err != nil {
			return err
		}
		attached, err := exists(ctx, tx,
			`SELECT 1 FROM attached_policies
			 WHERE entity_kind = ? AND entity_id = ? AND policy_id = ? LIMIT 1`,
			e.Kind, id, p.ID)
		if err != nil || attached {
			return err
		}
		var n int
		if err = tx.QueryRowContext(ctx,
			`SELECT COUNT(*) FROM attached_policies WHERE entity_kind = ? AND entity_id = ?`,
			e.Kind, id).Scan(&n); err != nil {
			return fmt.Errorf("count attached policies: %w", err)
		}
		if n >= maxAttached(e.Kind) {
			return contracts.ErrAttachedPolicyLimitExceeded
		}
		return exec(ctx, tx,
			`INSERT INTO attached_policies (entity_kind, entity_id, account_id, policy_id)
			 VALUES (?, ?, ?, ?)`, e.Kind, id, e.AccountID, p.ID)
	})
}

// DetachPolicy detaches the managed policy with the ARN from the entity,
// failing with contracts.ErrPolicyNotAttached when it is not attached.
func (s *Service) DetachPolicy(ctx context.Context, e contracts.Entity, arn string) error {
	return s.inTx(ctx, func(tx *sql.Tx) error {
		id, err := loadEntity(ctx, tx, e)
		if err != nil {
			return err
		}
		p, err := loadPolicy(ctx, tx, e.AccountID, arn)
		if errors.Is(err, contracts.ErrPolicyNotFound) {
			return contracts.ErrPolicyNotAttached
		}
		if err != nil {
			return err
		}
		n, err := execCount(ctx, tx,
			`DELETE FROM attached_policies
			 WHERE entity_kind = ? AND entity_id = ? AND policy_id = ?`, e.Kind, id, p.ID)
		if err != nil {
			return err
		}
		if n == 0 {
			return contracts.ErrPolicyNotAttached
		}
		return nil
	})
}

// ListAttachedPolicies lists the managed policies attached to the entity
// whose path starts with the prefix, in the order they were attached.
func (s *Service) ListAttachedPolicies(
	ctx context.Context,
	in contracts.ListAttachedPoliciesInput,
) (*contracts.Page[contracts.AttachedPolicy], error) {
	var out *contracts.Page[contracts.AttachedPolicy]
	err := s.inTx(ctx, func(tx *sql.Tx) error {
		id, err := loadEntity(ctx, tx, in.Entity)
		if err != nil {
			return err
		}
		scope := string(in.Entity.Kind) + ":" + id + ":" + in.PathPrefix
		after, err := decodeIntMarker(in.Marker, in.Entity.AccountID, listAttached, scope)
		if err != nil {
			return err
		}
		rows, err := queryAll(ctx, tx, func(r scanner) (cursored[contracts.AttachedPolicy], error) {
			var (
				row                 int64
				account, path, name string
			)
			sErr := r.Scan(&row, &account, &path, &name)
			return cursored[contracts.AttachedPolicy]{
				item: contracts.AttachedPolicy{
					Name: name, ARN: contracts.PolicyARN(account, path, name),
				},
				cursor: strconv.FormatInt(row, 10),
			}, sErr
		},
			`SELECT a.rowid, p.account_id, p.path, p.name
			 FROM attached_policies a JOIN policies p ON p.id = a.policy_id
			 WHERE a.entity_kind = ? AND a.entity_id = ? AND a.rowid > ?
			   AND substr(p.path, 1, length(?)) = ?
			 ORDER BY a.rowid LIMIT ?`,
			in.Entity.Kind, id, after, in.PathPrefix, in.PathPrefix, in.MaxItems+1)
		if err != nil {
			return err
		}
		out = paginate(rows, in.MaxItems, in.Entity.AccountID, listAttached, scope)
		return nil
	})
	return out, err
}

// PutInlinePolicy embeds the policy in the entity, replacing one of the same
// name, failing with contracts.ErrInlinePolicySizeExceeded when the entity's
// inline policies would then exceed its kind's aggregate size.
func (s *Service) PutInlinePolicy(
	ctx context.Context,
	e contracts.Entity,
	name, document string,
) error {
	return s.inTx(ctx, func(tx *sql.Tx) error {
		id, err := loadEntity(ctx, tx, e)
		if err != nil {
			return err
		}
		others, err := queryAll(ctx, tx, func(r scanner) (string, error) {
			var d string
			return d, r.Scan(&d)
		},
			`SELECT document FROM inline_policies
			 WHERE entity_kind = ? AND entity_id = ? AND name <> ?`, e.Kind, id, name)
		if err != nil {
			return err
		}
		size := contracts.PolicySize(document)
		for _, d := range others {
			size += contracts.PolicySize(d)
		}
		if size > maxInlineSize(e.Kind) {
			return contracts.ErrInlinePolicySizeExceeded
		}
		return exec(ctx, tx,
			`INSERT INTO inline_policies (entity_kind, entity_id, name, document)
			 VALUES (?, ?, ?, ?)
			 ON CONFLICT (entity_kind, entity_id, name) DO UPDATE SET document = excluded.document`,
			e.Kind, id, name, document)
	})
}

// GetInlinePolicy returns the entity's inline policy with the name.
func (s *Service) GetInlinePolicy(
	ctx context.Context,
	e contracts.Entity,
	name string,
) (*contracts.InlinePolicy, error) {
	var out *contracts.InlinePolicy
	err := s.inTx(ctx, func(tx *sql.Tx) error {
		id, err := loadEntity(ctx, tx, e)
		if err != nil {
			return err
		}
		p := contracts.InlinePolicy{Name: name}
		err = tx.QueryRowContext(ctx,
			`SELECT document FROM inline_policies
			 WHERE entity_kind = ? AND entity_id = ? AND name = ?`, e.Kind, id, name,
		).Scan(&p.Document)
		switch {
		case errors.Is(err, sql.ErrNoRows):
			return contracts.ErrInlinePolicyNotFound
		case err != nil:
			return fmt.Errorf("read inline policy: %w", err)
		}
		out = &p
		return nil
	})
	return out, err
}

// ListInlinePolicies lists the names of the entity's inline policies in
// order.
func (s *Service) ListInlinePolicies(
	ctx context.Context,
	in contracts.ListInlinePoliciesInput,
) (*contracts.Page[string], error) {
	var out *contracts.Page[string]
	err := s.inTx(ctx, func(tx *sql.Tx) error {
		id, err := loadEntity(ctx, tx, in.Entity)
		if err != nil {
			return err
		}
		scope := string(in.Entity.Kind) + ":" + id
		after, err := decodeMarker(in.Marker, in.Entity.AccountID, listInline, scope)
		if err != nil {
			return err
		}
		rows, err := queryAll(ctx, tx, func(r scanner) (cursored[string], error) {
			var n string
			sErr := r.Scan(&n)
			return cursored[string]{item: n, cursor: n}, sErr
		},
			`SELECT name FROM inline_policies
			 WHERE entity_kind = ? AND entity_id = ? AND (? = '' OR name > ?)
			 ORDER BY name LIMIT ?`, in.Entity.Kind, id, after, after, in.MaxItems+1)
		if err != nil {
			return err
		}
		out = paginate(rows, in.MaxItems, in.Entity.AccountID, listInline, scope)
		return nil
	})
	return out, err
}

// DeleteInlinePolicy deletes the entity's inline policy with the name.
func (s *Service) DeleteInlinePolicy(ctx context.Context, e contracts.Entity, name string) error {
	return s.inTx(ctx, func(tx *sql.Tx) error {
		id, err := loadEntity(ctx, tx, e)
		if err != nil {
			return err
		}
		n, err := execCount(ctx, tx,
			`DELETE FROM inline_policies WHERE entity_kind = ? AND entity_id = ? AND name = ?`,
			e.Kind, id, name)
		if err != nil {
			return err
		}
		if n == 0 {
			return contracts.ErrInlinePolicyNotFound
		}
		return nil
	})
}

// EffectivePolicies returns the identity policy documents in effect for the
// principal.
func (s *Service) EffectivePolicies(ctx context.Context, p *contracts.Principal) ([]string, error) {
	var out []string
	err := s.inTx(ctx, func(tx *sql.Tx) error {
		var eErr error
		out, eErr = effectivePolicies(ctx, tx, p)
		return eErr
	})
	return out, err
}

// effectivePolicies returns the inline policies, in order of their names,
// then the default versions of the attached managed policies, in the order
// they were attached, of the principal's user or its session's role. The
// root user has none.
func effectivePolicies(ctx context.Context, tx *sql.Tx, p *contracts.Principal) ([]string, error) {
	var kind contracts.EntityKind
	id := p.UserID
	switch p.Kind {
	case contracts.PrincipalUser:
		kind = contracts.EntityUser
	case contracts.PrincipalRoleSession:
		kind = contracts.EntityRole
		id, _, _ = strings.Cut(p.UserID, ":")
	default:
		return nil, nil
	}
	scan := func(r scanner) (string, error) {
		var d string
		return d, r.Scan(&d)
	}
	inline, err := queryAll(ctx, tx, scan,
		`SELECT document FROM inline_policies WHERE entity_kind = ? AND entity_id = ?
		 ORDER BY name`, kind, id)
	if err != nil {
		return nil, err
	}
	managed, err := queryAll(ctx, tx, scan,
		`SELECT v.document FROM attached_policies a
		 JOIN policies p ON p.id = a.policy_id
		 JOIN policy_versions v ON v.policy_id = p.id AND v.version = p.default_version
		 WHERE a.entity_kind = ? AND a.entity_id = ? ORDER BY a.rowid`, kind, id)
	if err != nil {
		return nil, err
	}
	return append(inline, managed...), nil
}
