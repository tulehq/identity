package sqlimpl

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strconv"

	"tule.dev/identity/internal/contracts"
)

// accessKeyTaken and sessionKeyTaken find an access key ID among the users'
// keys and the role sessions'. Every key ID is unique across both, so a key
// ID names one principal.
const (
	accessKeyTaken  = `SELECT 1 FROM access_keys WHERE id = ? LIMIT 1`
	sessionKeyTaken = `SELECT 1 FROM role_sessions WHERE access_key_id = ? LIMIT 1`
)

// CreateAccessKey creates an Active access key for the IAM user of the account,
// failing with contracts.ErrAccessKeyLimitExceeded when the IAM user has
// contracts.MaxAccessKeysPerUser keys already. The key is the only one
// returned with its secret.
func (s *Service) CreateAccessKey(
	ctx context.Context,
	accountID, userName string,
) (*contracts.AccessKey, error) {
	var out *contracts.AccessKey
	err := s.inTx(ctx, func(tx *sql.Tx) error {
		u, err := loadUser(ctx, tx, accountID, userName)
		if err != nil {
			return err
		}
		var n int
		if err = tx.QueryRowContext(ctx,
			`SELECT COUNT(*) FROM access_keys WHERE user_id = ?`, u.ID).Scan(&n); err != nil {
			return fmt.Errorf("count access keys: %w", err)
		}
		if n >= contracts.MaxAccessKeysPerUser {
			return contracts.ErrAccessKeyLimitExceeded
		}

		id, err := s.unusedID(ctx, tx, newAccessKeyID, accessKeyTaken, sessionKeyTaken)
		if err != nil {
			return err
		}
		secret, err := newSecret()
		if err != nil {
			return err
		}
		k := contracts.AccessKey{
			CreateDate:      unstamp(stamp(s.now())),
			ID:              id,
			UserName:        u.Name,
			Status:          contracts.StatusActive,
			SecretAccessKey: secret,
		}
		if err = exec(ctx, tx,
			`INSERT INTO access_keys (id, user_id, secret, status, created_at)
			 VALUES (?, ?, ?, ?, ?)`,
			k.ID, u.ID, k.SecretAccessKey, k.Status, stamp(k.CreateDate)); err != nil {
			return err
		}
		out = &k
		return nil
	})
	return out, err
}

// ListAccessKeys lists the IAM user's access keys in the order they were
// created, without their secrets.
func (s *Service) ListAccessKeys(
	ctx context.Context,
	in contracts.ListAccessKeysInput,
) (*contracts.Page[contracts.AccessKey], error) {
	var out *contracts.Page[contracts.AccessKey]
	err := s.inTx(ctx, func(tx *sql.Tx) error {
		u, err := loadUser(ctx, tx, in.AccountID, in.UserName)
		if err != nil {
			return err
		}
		// The marker is scoped to the IAM user's ID, which a user created again
		// under the same name does not have.
		after, err := decodeIntMarker(in.Marker, in.AccountID, listKeys, u.ID)
		if err != nil {
			return err
		}
		rows, err := queryAll(ctx, tx, func(r scanner) (cursored[contracts.AccessKey], error) {
			var (
				row     int64
				created int64
				k       = contracts.AccessKey{UserName: u.Name}
			)
			sErr := r.Scan(&row, &k.ID, &k.Status, &created)
			k.CreateDate = unstamp(created)
			return cursored[contracts.AccessKey]{
				item: k, cursor: strconv.FormatInt(row, 10),
			}, sErr
		},
			`SELECT rowid, id, status, created_at FROM access_keys
			 WHERE user_id = ? AND rowid > ? ORDER BY rowid LIMIT ?`,
			u.ID, after, in.MaxItems+1)
		if err != nil {
			return err
		}
		out = paginate(rows, in.MaxItems, in.AccountID, listKeys, u.ID)
		return nil
	})
	return out, err
}

// UpdateAccessKey sets the status of one of the IAM user's access keys.
func (s *Service) UpdateAccessKey(
	ctx context.Context,
	accountID, userName, keyID, status string,
) error {
	return s.inTx(ctx, func(tx *sql.Tx) error {
		u, err := loadUser(ctx, tx, accountID, userName)
		if err != nil {
			return err
		}
		n, err := execCount(ctx, tx,
			`UPDATE access_keys SET status = ? WHERE id = ? AND user_id = ?`,
			status, keyID, u.ID)
		if err != nil {
			return err
		}
		if n == 0 {
			return contracts.ErrAccessKeyNotFound
		}
		return nil
	})
}

// DeleteAccessKey deletes one of the IAM user's access keys, with the record of
// its last use.
func (s *Service) DeleteAccessKey(ctx context.Context, accountID, userName, keyID string) error {
	return s.inTx(ctx, func(tx *sql.Tx) error {
		u, err := loadUser(ctx, tx, accountID, userName)
		if err != nil {
			return err
		}
		n, err := execCount(ctx, tx,
			`DELETE FROM access_keys WHERE id = ? AND user_id = ?`, keyID, u.ID)
		if err != nil {
			return err
		}
		if n == 0 {
			return contracts.ErrAccessKeyNotFound
		}
		return exec(ctx, tx, `DELETE FROM key_last_used WHERE access_key_id = ?`, keyID)
	})
}

// GetAccessKeyLastUsed reports the last use of a long-term key of the
// account: the root user's, when the account is its, or a user's. Any other
// key, a role session's included, is contracts.ErrAccessKeyNotFound.
func (s *Service) GetAccessKeyLastUsed(
	ctx context.Context,
	accountID, keyID string,
) (*contracts.KeyLastUsed, error) {
	var out *contracts.KeyLastUsed
	err := s.inTx(ctx, func(tx *sql.Tx) error {
		var used contracts.KeyLastUsed
		if keyID != s.root.AccessKeyID || accountID != s.root.AccountID {
			err := tx.QueryRowContext(ctx,
				`SELECT u.name FROM access_keys k JOIN users u ON u.id = k.user_id
				 WHERE k.id = ? AND u.account_id = ?`, keyID, accountID,
			).Scan(&used.UserName)
			switch {
			case errors.Is(err, sql.ErrNoRows):
				return contracts.ErrAccessKeyNotFound
			case err != nil:
				return fmt.Errorf("read access key: %w", err)
			}
		}

		var at int64
		err := tx.QueryRowContext(ctx,
			`SELECT service, region, used_at FROM key_last_used WHERE access_key_id = ?`, keyID,
		).Scan(&used.Service, &used.Region, &at)
		switch {
		case errors.Is(err, sql.ErrNoRows):
		case err != nil:
			return fmt.Errorf("read last use: %w", err)
		default:
			used.LastUsed = unstamp(at)
		}
		out = &used
		return nil
	})
	return out, err
}

// RecordKeyUse records the use of the root user's key or a user's key now.
// A role session's key, or a key since deleted, is not recorded.
func (s *Service) RecordKeyUse(ctx context.Context, keyID, service, region string) error {
	return s.inTx(ctx, func(tx *sql.Tx) error {
		if keyID != s.root.AccessKeyID {
			known, err := exists(ctx, tx, accessKeyTaken, keyID)
			if err != nil {
				return err
			}
			if !known {
				return nil
			}
		}
		return exec(ctx, tx,
			`INSERT INTO key_last_used (access_key_id, service, region, used_at)
			 VALUES (?, ?, ?, ?)
			 ON CONFLICT (access_key_id) DO UPDATE
			 SET service = excluded.service, region = excluded.region,
			     used_at = excluded.used_at`,
			keyID, service, region, stamp(s.now()))
	})
}
