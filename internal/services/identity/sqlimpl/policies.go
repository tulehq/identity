package sqlimpl

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strconv"

	"tule.dev/identity/internal/contracts"
)

// policyRow is a managed policy as the store keeps it. Its UpdateDate is
// when its newest version was created, as the IAM model documents it.
type policyRow struct {
	contracts.ManagedPolicy
	defaultVersion int64
	nextVersion    int64
}

// versionID is how a policy version is named on the wire: v1, v2, ...
func versionID(n int64) string {
	return "v" + strconv.FormatInt(n, 10)
}

// parseVersionID reads a version ID this store issues. Any other ID names no
// version.
func parseVersionID(id string) (int64, bool) {
	if len(id) < 2 || id[0] != 'v' || id[1] == '0' {
		return 0, false
	}
	n, err := strconv.ParseInt(id[1:], 10, 64)
	return n, err == nil && n > 0
}

const policyColumns = `p.id, p.account_id, p.name, p.path, p.description, p.default_version,
	p.next_version, p.created_at,
	(SELECT MAX(v.created_at) FROM policy_versions v WHERE v.policy_id = p.id),
	(SELECT COUNT(*) FROM attached_policies a WHERE a.policy_id = p.id AND a.account_id = ?)`

func scanPolicy(r scanner) (policyRow, error) {
	var (
		p                policyRow
		created, updated int64
	)
	err := r.Scan(&p.ID, &p.AccountID, &p.Name, &p.Path, &p.Description, &p.defaultVersion,
		&p.nextVersion, &created, &updated, &p.AttachmentCount)
	p.CreateDate = unstamp(created)
	p.UpdateDate = unstamp(updated)
	p.ARN = contracts.PolicyARN(p.AccountID, p.Path, p.Name)
	p.DefaultVersionID = versionID(p.defaultVersion)
	return p, err
}

// loadPolicy reads the managed policy with the ARN that the account can see:
// its own, or an AWS managed one. Its AttachmentCount counts the account's
// attachments.
func loadPolicy(ctx context.Context, tx *sql.Tx, accountID, arn string) (*policyRow, error) {
	owner, path, name, ok := contracts.ParsePolicyARN(arn)
	if !ok || (owner != accountID && owner != contracts.AWSAccount) {
		return nil, contracts.ErrPolicyNotFound
	}
	p, err := scanPolicy(tx.QueryRowContext(ctx,
		`SELECT `+policyColumns+` FROM policies p
		 WHERE p.account_id = ? AND p.name = ? AND p.path = ?`,
		accountID, owner, name, path))
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return nil, contracts.ErrPolicyNotFound
	case err != nil:
		return nil, fmt.Errorf("read policy: %w", err)
	}
	return &p, nil
}

// loadOwnPolicy is loadPolicy for a change, which only a customer managed
// policy of the account takes: an AWS managed one is
// contracts.ErrAWSManagedPolicy.
func loadOwnPolicy(ctx context.Context, tx *sql.Tx, accountID, arn string) (*policyRow, error) {
	p, err := loadPolicy(ctx, tx, accountID, arn)
	if err != nil {
		return nil, err
	}
	if p.AccountID == contracts.AWSAccount {
		return nil, contracts.ErrAWSManagedPolicy
	}
	return p, nil
}

// CreatePolicy creates a customer managed policy whose v1 is the document,
// failing with contracts.ErrPolicyExists when the account has one with the
// name, compared without regard to case.
func (s *Service) CreatePolicy(
	ctx context.Context,
	in contracts.CreatePolicyInput,
) (*contracts.ManagedPolicy, error) {
	var out *contracts.ManagedPolicy
	err := s.inTx(ctx, func(tx *sql.Tx) error {
		taken, err := exists(ctx, tx,
			`SELECT 1 FROM policies WHERE account_id = ? AND name = ? COLLATE NOCASE LIMIT 1`,
			in.AccountID, in.Name)
		if err != nil {
			return err
		}
		if taken {
			return contracts.ErrPolicyExists
		}
		id, err := s.unusedID(ctx, tx, newPolicyID, `SELECT 1 FROM policies WHERE id = ? LIMIT 1`)
		if err != nil {
			return err
		}
		now := unstamp(stamp(s.now()))
		p := contracts.ManagedPolicy{
			CreateDate:       now,
			UpdateDate:       now,
			AccountID:        in.AccountID,
			ID:               id,
			Name:             in.Name,
			Path:             in.Path,
			ARN:              contracts.PolicyARN(in.AccountID, in.Path, in.Name),
			Description:      in.Description,
			DefaultVersionID: versionID(1),
			Tags:             in.Tags,
		}
		if err = exec(ctx, tx,
			`INSERT INTO policies (id, account_id, name, path, description, default_version,
			                       next_version, created_at)
			 VALUES (?, ?, ?, ?, ?, 1, 2, ?)`,
			p.ID, p.AccountID, p.Name, p.Path, p.Description, stamp(now)); err != nil {
			return err
		}
		if err = exec(ctx, tx,
			`INSERT INTO policy_versions (policy_id, version, document, created_at)
			 VALUES (?, 1, ?, ?)`, p.ID, in.Document, stamp(now)); err != nil {
			return err
		}
		if err = putTagsOn(ctx, tx, policyTags, p.ID, in.Tags); err != nil {
			return err
		}
		out = &p
		return nil
	})
	return out, err
}

// GetPolicy returns the managed policy with the ARN, with its tags.
func (s *Service) GetPolicy(
	ctx context.Context,
	accountID, arn string,
) (*contracts.ManagedPolicy, error) {
	var out *contracts.ManagedPolicy
	err := s.inTx(ctx, func(tx *sql.Tx) error {
		p, err := loadPolicy(ctx, tx, accountID, arn)
		if err != nil {
			return err
		}
		if p.Tags, err = tagsOf(ctx, tx, policyTags, p.ID); err != nil {
			return err
		}
		out = &p.ManagedPolicy
		return nil
	})
	return out, err
}

// ListPolicies lists the managed policies the account can see, in order of
// their names without regard to case, then their IDs.
func (s *Service) ListPolicies(
	ctx context.Context,
	in contracts.ListPoliciesInput,
) (*contracts.Page[contracts.ManagedPolicy], error) {
	owners := map[string][]string{
		contracts.PolicyScopeAll:   {in.AccountID, contracts.AWSAccount},
		contracts.PolicyScopeAWS:   {contracts.AWSAccount, contracts.AWSAccount},
		contracts.PolicyScopeLocal: {in.AccountID, in.AccountID},
	}[in.Scope]
	if owners == nil {
		return nil, fmt.Errorf("list policies: unknown scope %q", in.Scope)
	}
	scope := in.Scope + ":" + strconv.FormatBool(in.OnlyAttached) + ":" + in.PathPrefix

	var out *contracts.Page[contracts.ManagedPolicy]
	err := s.inTx(ctx, func(tx *sql.Tx) error {
		after, err := decodeMarker(in.Marker, in.AccountID, listPolicies, scope)
		if err != nil {
			return err
		}
		afterName, afterID := splitCursor(after)
		rows, err := queryAll(ctx, tx, func(r scanner) (cursored[contracts.ManagedPolicy], error) {
			p, sErr := scanPolicy(r)
			return cursored[contracts.ManagedPolicy]{
				item: p.ManagedPolicy, cursor: joinCursor(p.Name, p.ID),
			}, sErr
		},
			`SELECT `+policyColumns+` FROM policies p
			 WHERE p.account_id IN (?, ?) AND substr(p.path, 1, length(?)) = ?
			   AND (? = 0 OR EXISTS (SELECT 1 FROM attached_policies a
			                         WHERE a.policy_id = p.id AND a.account_id = ?))
			   AND (? = '' OR (p.name COLLATE NOCASE, p.id) > (? COLLATE NOCASE, ?))
			 ORDER BY p.name COLLATE NOCASE, p.id LIMIT ?`,
			in.AccountID, owners[0], owners[1], in.PathPrefix, in.PathPrefix,
			in.OnlyAttached, in.AccountID,
			after, afterName, afterID, in.MaxItems+1)
		if err != nil {
			return err
		}
		out = paginate(rows, in.MaxItems, in.AccountID, listPolicies, scope)
		return nil
	})
	return out, err
}

// DeletePolicy deletes a customer managed policy with its default version
// and tags.
func (s *Service) DeletePolicy(ctx context.Context, accountID, arn string) error {
	return s.inTx(ctx, func(tx *sql.Tx) error {
		p, err := loadOwnPolicy(ctx, tx, accountID, arn)
		if err != nil {
			return err
		}
		// A customer managed policy attaches only within its account, so
		// its AttachmentCount is every attachment it has.
		if p.AttachmentCount > 0 {
			return contracts.ErrPolicyAttached
		}
		others, err := exists(ctx, tx,
			`SELECT 1 FROM policy_versions WHERE policy_id = ? AND version <> ? LIMIT 1`,
			p.ID, p.defaultVersion)
		if err != nil {
			return err
		}
		if others {
			return contracts.ErrPolicyHasVersions
		}
		for _, q := range []string{
			`DELETE FROM policy_versions WHERE policy_id = ?`,
			`DELETE FROM policy_tags WHERE policy_id = ?`,
			`DELETE FROM policies WHERE id = ?`,
		} {
			if err = exec(ctx, tx, q, p.ID); err != nil {
				return err
			}
		}
		return nil
	})
}

// CreatePolicyVersion adds the next version to a customer managed policy,
// as its default when setAsDefault.
func (s *Service) CreatePolicyVersion(
	ctx context.Context,
	accountID, arn, document string,
	setAsDefault bool,
) (*contracts.PolicyVersion, error) {
	var out *contracts.PolicyVersion
	err := s.inTx(ctx, func(tx *sql.Tx) error {
		p, err := loadOwnPolicy(ctx, tx, accountID, arn)
		if err != nil {
			return err
		}
		var n int
		if err = tx.QueryRowContext(ctx,
			`SELECT COUNT(*) FROM policy_versions WHERE policy_id = ?`, p.ID).Scan(&n); err != nil {
			return fmt.Errorf("count policy versions: %w", err)
		}
		if n >= contracts.MaxPolicyVersions {
			return contracts.ErrPolicyVersionLimitExceeded
		}
		now := unstamp(stamp(s.now()))
		v := p.nextVersion
		if err = exec(ctx, tx,
			`INSERT INTO policy_versions (policy_id, version, document, created_at)
			 VALUES (?, ?, ?, ?)`, p.ID, v, document, stamp(now)); err != nil {
			return err
		}
		def := p.defaultVersion
		if setAsDefault {
			def = v
		}
		if err = exec(ctx, tx,
			`UPDATE policies SET next_version = ?, default_version = ? WHERE id = ?`,
			v+1, def, p.ID); err != nil {
			return err
		}
		out = &contracts.PolicyVersion{
			CreateDate: now, VersionID: versionID(v), IsDefault: setAsDefault,
		}
		return nil
	})
	return out, err
}

// GetPolicyVersion returns a version of a managed policy with its document.
func (s *Service) GetPolicyVersion(
	ctx context.Context,
	accountID, arn, id string,
) (*contracts.PolicyVersion, error) {
	var out *contracts.PolicyVersion
	err := s.inTx(ctx, func(tx *sql.Tx) error {
		p, err := loadPolicy(ctx, tx, accountID, arn)
		if err != nil {
			return err
		}
		n, ok := parseVersionID(id)
		if !ok {
			return contracts.ErrPolicyVersionNotFound
		}
		var created int64
		v := contracts.PolicyVersion{VersionID: versionID(n), IsDefault: n == p.defaultVersion}
		err = tx.QueryRowContext(ctx,
			`SELECT document, created_at FROM policy_versions WHERE policy_id = ? AND version = ?`,
			p.ID, n).Scan(&v.Document, &created)
		switch {
		case errors.Is(err, sql.ErrNoRows):
			return contracts.ErrPolicyVersionNotFound
		case err != nil:
			return fmt.Errorf("read policy version: %w", err)
		}
		v.CreateDate = unstamp(created)
		out = &v
		return nil
	})
	return out, err
}

// ListPolicyVersions lists a managed policy's versions, newest first,
// without their documents.
func (s *Service) ListPolicyVersions(
	ctx context.Context,
	in contracts.ListPolicyVersionsInput,
) (*contracts.Page[contracts.PolicyVersion], error) {
	var out *contracts.Page[contracts.PolicyVersion]
	err := s.inTx(ctx, func(tx *sql.Tx) error {
		p, err := loadPolicy(ctx, tx, in.AccountID, in.PolicyARN)
		if err != nil {
			return err
		}
		before, err := decodeIntMarker(in.Marker, in.AccountID, listPolicyVersions, p.ID)
		if err != nil {
			return err
		}
		rows, err := queryAll(ctx, tx, func(r scanner) (cursored[contracts.PolicyVersion], error) {
			var n, created int64
			sErr := r.Scan(&n, &created)
			return cursored[contracts.PolicyVersion]{
				item: contracts.PolicyVersion{
					CreateDate: unstamp(created),
					VersionID:  versionID(n),
					IsDefault:  n == p.defaultVersion,
				},
				cursor: strconv.FormatInt(n, 10),
			}, sErr
		},
			`SELECT version, created_at FROM policy_versions
			 WHERE policy_id = ? AND (? = 0 OR version < ?) ORDER BY version DESC LIMIT ?`,
			p.ID, before, before, in.MaxItems+1)
		if err != nil {
			return err
		}
		out = paginate(rows, in.MaxItems, in.AccountID, listPolicyVersions, p.ID)
		return nil
	})
	return out, err
}

// DeletePolicyVersion deletes a version of a customer managed policy other
// than its default.
func (s *Service) DeletePolicyVersion(ctx context.Context, accountID, arn, id string) error {
	return s.inTx(ctx, func(tx *sql.Tx) error {
		p, err := loadOwnPolicy(ctx, tx, accountID, arn)
		if err != nil {
			return err
		}
		n, ok := parseVersionID(id)
		if !ok {
			return contracts.ErrPolicyVersionNotFound
		}
		if n == p.defaultVersion {
			return contracts.ErrDefaultPolicyVersion
		}
		deleted, err := execCount(ctx, tx,
			`DELETE FROM policy_versions WHERE policy_id = ? AND version = ?`, p.ID, n)
		if err != nil {
			return err
		}
		if deleted == 0 {
			return contracts.ErrPolicyVersionNotFound
		}
		return nil
	})
}

// SetDefaultPolicyVersion makes a version of a customer managed policy its
// default.
func (s *Service) SetDefaultPolicyVersion(ctx context.Context, accountID, arn, id string) error {
	return s.inTx(ctx, func(tx *sql.Tx) error {
		p, err := loadOwnPolicy(ctx, tx, accountID, arn)
		if err != nil {
			return err
		}
		n, ok := parseVersionID(id)
		if !ok {
			return contracts.ErrPolicyVersionNotFound
		}
		found, err := exists(ctx, tx,
			`SELECT 1 FROM policy_versions WHERE policy_id = ? AND version = ? LIMIT 1`, p.ID, n)
		if err != nil {
			return err
		}
		if !found {
			return contracts.ErrPolicyVersionNotFound
		}
		return exec(ctx, tx,
			`UPDATE policies SET default_version = ? WHERE id = ?`, n, p.ID)
	})
}
