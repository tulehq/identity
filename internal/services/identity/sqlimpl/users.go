package sqlimpl

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"tule.dev/identity/internal/contracts"
)

const userColumns = `rowid, id, account_id, name, path, created_at FROM users`

func scanUser(r scanner) (cursored[contracts.User], error) {
	var (
		row     int64
		created int64
		u       contracts.User
	)
	err := r.Scan(&row, &u.ID, &u.AccountID, &u.Name, &u.Path, &created)
	u.CreateDate = unstamp(created)
	u.ARN = userARN(u.AccountID, u.Path, u.Name)
	return cursored[contracts.User]{item: u, cursor: u.Name}, err
}

// loadUser reads the IAM user of the account with the name, compared without
// regard to case, failing with contracts.ErrUserNotFound when there is none.
func loadUser(ctx context.Context, tx *sql.Tx, accountID, name string) (*contracts.User, error) {
	c, err := scanUser(tx.QueryRowContext(ctx,
		`SELECT `+userColumns+` WHERE account_id = ? AND name = ? COLLATE NOCASE`,
		accountID, name))
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return nil, contracts.ErrUserNotFound
	case err != nil:
		return nil, fmt.Errorf("read user: %w", err)
	}
	return &c.item, nil
}

// CreateUser creates a user in the account with the tags, failing with
// contracts.ErrUserExists when one has the name already, compared without
// regard to case.
func (s *Service) CreateUser(
	ctx context.Context,
	accountID, name, path string,
	tags []contracts.Tag,
) (*contracts.User, error) {
	var out *contracts.User
	err := s.inTx(ctx, func(tx *sql.Tx) error {
		taken, err := exists(ctx, tx,
			`SELECT 1 FROM users WHERE account_id = ? AND name = ? COLLATE NOCASE LIMIT 1`,
			accountID, name)
		if err != nil {
			return err
		}
		if taken {
			return contracts.ErrUserExists
		}

		id, err := s.unusedID(ctx, tx, newUserID, `SELECT 1 FROM users WHERE id = ? LIMIT 1`)
		if err != nil {
			return err
		}
		u := contracts.User{
			CreateDate: unstamp(stamp(s.now())),
			AccountID:  accountID,
			ID:         id,
			Name:       name,
			Path:       path,
			ARN:        userARN(accountID, path, name),
		}
		if err = exec(ctx, tx,
			`INSERT INTO users (id, account_id, name, path, created_at) VALUES (?, ?, ?, ?, ?)`,
			u.ID, u.AccountID, u.Name, u.Path, stamp(u.CreateDate)); err != nil {
			return err
		}
		if err = putTags(ctx, tx, u.ID, tags); err != nil {
			return err
		}
		out = &u
		return nil
	})
	return out, err
}

// GetUser returns the IAM user of the account with the name, with its tags.
func (s *Service) GetUser(ctx context.Context, accountID, name string) (*contracts.User, error) {
	var out *contracts.User
	err := s.inTx(ctx, func(tx *sql.Tx) error {
		u, err := loadUser(ctx, tx, accountID, name)
		if err != nil {
			return err
		}
		if u.Tags, err = tagsOf(ctx, tx, userTags, u.ID); err != nil {
			return err
		}
		out = u
		return nil
	})
	return out, err
}

// ListUsers lists the users of the account whose path starts with the
// prefix, in order of their names without regard to case.
func (s *Service) ListUsers(
	ctx context.Context,
	in contracts.ListUsersInput,
) (*contracts.Page[contracts.User], error) {
	var out *contracts.Page[contracts.User]
	err := s.inTx(ctx, func(tx *sql.Tx) error {
		after, err := decodeMarker(in.Marker, in.AccountID, listUsers, in.PathPrefix)
		if err != nil {
			return err
		}
		// substr rather than LIKE, which ignores case and treats % and _ in
		// the prefix as wildcards.
		rows, err := queryAll(ctx, tx, scanUser,
			`SELECT `+userColumns+`
			 WHERE account_id = ? AND substr(path, 1, length(?)) = ?
			   AND (? = '' OR name > ? COLLATE NOCASE)
			 ORDER BY name COLLATE NOCASE LIMIT ?`,
			in.AccountID, in.PathPrefix, in.PathPrefix, after, after, in.MaxItems+1)
		if err != nil {
			return err
		}
		out = paginate(rows, in.MaxItems, in.AccountID, listUsers, in.PathPrefix)
		return nil
	})
	return out, err
}

// DeleteUser deletes the IAM user of the account with the name, failing with
// contracts.ErrDeleteConflict while it has access keys, and
// contracts.ErrHasAttachedPolicies or contracts.ErrHasInlinePolicies while it
// has policies, as IAM requires them to be removed first.
func (s *Service) DeleteUser(ctx context.Context, accountID, name string) error {
	return s.inTx(ctx, func(tx *sql.Tx) error {
		u, err := loadUser(ctx, tx, accountID, name)
		if err != nil {
			return err
		}
		hasKeys, err := exists(ctx, tx,
			`SELECT 1 FROM access_keys WHERE user_id = ? LIMIT 1`, u.ID)
		if err != nil {
			return err
		}
		if hasKeys {
			return contracts.ErrDeleteConflict
		}
		if err = checkNoPolicies(ctx, tx, contracts.EntityUser, u.ID); err != nil {
			return err
		}
		if err = exec(ctx, tx, `DELETE FROM user_tags WHERE user_id = ?`, u.ID); err != nil {
			return err
		}
		return exec(ctx, tx, `DELETE FROM users WHERE id = ?`, u.ID)
	})
}

// maxIDAttempts bounds the draws for an ID nothing has. A collision among
// 32^16 IDs is already unlikely; several in a row mean something is wrong
// with the random source.
const maxIDAttempts = 5

// unusedID draws IDs with gen until taken, a SELECT 1 ... WHERE id = ?,
// finds none with it. An ID equal to the root user's key ID counts as
// taken.
func (s *Service) unusedID(
	ctx context.Context,
	tx *sql.Tx,
	gen func() (string, error),
	taken ...string,
) (string, error) {
	for range maxIDAttempts {
		id, err := gen()
		if err != nil {
			return "", err
		}
		if id == s.root.AccessKeyID {
			continue
		}
		free := true
		for _, q := range taken {
			used, qErr := exists(ctx, tx, q, id)
			if qErr != nil {
				return "", qErr
			}
			free = free && !used
		}
		if free {
			return id, nil
		}
	}
	return "", fmt.Errorf("no unused ID after %d attempts", maxIDAttempts)
}
