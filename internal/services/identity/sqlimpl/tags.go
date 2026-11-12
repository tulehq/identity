package sqlimpl

import (
	"context"
	"database/sql"
	"fmt"
	"strconv"

	"tule.dev/identity/internal/contracts"
)

// scanTag reads a tag; its cursor is set by the listing that pages it.
func scanTag(r scanner) (cursored[contracts.Tag], error) {
	var t contracts.Tag
	err := r.Scan(&t.Key, &t.Value)
	return cursored[contracts.Tag]{item: t}, err
}

// putTags sets tags on the IAM user, replacing the tag with the same key without
// regard to case, key and value both, as IAM replaces it.
func putTags(ctx context.Context, tx *sql.Tx, userID string, tags []contracts.Tag) error {
	for _, t := range tags {
		if err := exec(ctx, tx,
			`INSERT INTO user_tags (user_id, key, value) VALUES (?, ?, ?)
			 ON CONFLICT (user_id, key) DO UPDATE SET key = excluded.key, value = excluded.value`,
			userID, t.Key, t.Value); err != nil {
			return err
		}
	}
	return nil
}

// TagUser sets tags on the IAM user, failing with contracts.ErrTagLimitExceeded,
// and setting none, when it would then carry more than
// contracts.MaxTagsPerUser.
func (s *Service) TagUser(
	ctx context.Context,
	accountID, userName string,
	tags []contracts.Tag,
) error {
	return s.inTx(ctx, func(tx *sql.Tx) error {
		u, err := loadUser(ctx, tx, accountID, userName)
		if err != nil {
			return err
		}
		if err = putTags(ctx, tx, u.ID, tags); err != nil {
			return err
		}
		var n int
		if err = tx.QueryRowContext(ctx,
			`SELECT COUNT(*) FROM user_tags WHERE user_id = ?`, u.ID).Scan(&n); err != nil {
			return fmt.Errorf("count tags: %w", err)
		}
		if n > contracts.MaxTagsPerUser {
			// Returning an error rolls the new tags back.
			return contracts.ErrTagLimitExceeded
		}
		return nil
	})
}

// UntagUser removes the tags with the keys from the IAM user.
func (s *Service) UntagUser(
	ctx context.Context,
	accountID, userName string,
	keys []string,
) error {
	return s.inTx(ctx, func(tx *sql.Tx) error {
		u, err := loadUser(ctx, tx, accountID, userName)
		if err != nil {
			return err
		}
		for _, k := range keys {
			if err = exec(ctx, tx,
				`DELETE FROM user_tags WHERE user_id = ? AND key = ?`, u.ID, k); err != nil {
				return err
			}
		}
		return nil
	})
}

// ListUserTags lists the IAM user's tags in order of their keys, without regard
// to case. A page resumes at an offset, since a key may be 128 characters of
// any script, too long to carry in a marker; a tag set or removed between
// pages can so shift the next page by one.
func (s *Service) ListUserTags(
	ctx context.Context,
	in contracts.ListUserTagsInput,
) (*contracts.Page[contracts.Tag], error) {
	var out *contracts.Page[contracts.Tag]
	err := s.inTx(ctx, func(tx *sql.Tx) error {
		u, err := loadUser(ctx, tx, in.AccountID, in.UserName)
		if err != nil {
			return err
		}
		offset, err := decodeIntMarker(in.Marker, in.AccountID, listTags, u.ID)
		if err != nil {
			return err
		}
		rows, err := queryAll(ctx, tx, scanTag,
			`SELECT key, value FROM user_tags WHERE user_id = ? ORDER BY key LIMIT ? OFFSET ?`,
			u.ID, in.MaxItems+1, offset)
		if err != nil {
			return err
		}
		for i := range rows {
			rows[i].cursor = strconv.FormatInt(offset+int64(i)+1, 10)
		}
		out = paginate(rows, in.MaxItems, in.AccountID, listTags, u.ID)
		return nil
	})
	return out, err
}
