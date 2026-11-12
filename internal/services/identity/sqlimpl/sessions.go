package sqlimpl

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"

	"tule.dev/sigv4"

	"tule.dev/identity/internal/contracts"
)

// CreateRoleSession creates a session of contracts.OrganizationRoleName in
// the account, valid for the duration from now, with new temporary
// credentials.
func (s *Service) CreateRoleSession(
	ctx context.Context,
	in contracts.CreateRoleSessionInput,
) (*contracts.RoleSession, error) {
	var out *contracts.RoleSession
	err := s.inTx(ctx, func(tx *sql.Tx) error {
		id, err := s.unusedID(ctx, tx, newSessionKeyID, accessKeyTaken, sessionKeyTaken)
		if err != nil {
			return err
		}
		secret, err := newSecret()
		if err != nil {
			return err
		}
		token, err := newSessionToken()
		if err != nil {
			return err
		}
		now := unstamp(stamp(s.now()))
		rs := contracts.RoleSession{
			Expiration:      now.Add(in.Duration),
			AccessKeyID:     id,
			SecretAccessKey: secret,
			SessionToken:    token,
			ARN:             assumedRoleARN(in.AccountID, in.SessionName),
			AssumedRoleID:   roleID(in.AccountID) + ":" + in.SessionName,
		}
		if err = exec(ctx, tx,
			`INSERT INTO role_sessions
			 (access_key_id, account_id, session_name, secret, token_sha256, expires_at,
			  created_at)
			 VALUES (?, ?, ?, ?, ?, ?, ?)`,
			rs.AccessKeyID, in.AccountID, in.SessionName, rs.SecretAccessKey,
			tokenHash(token), stamp(rs.Expiration), stamp(now)); err != nil {
			return err
		}
		out = &rs
		return nil
	})
	return out, err
}

func tokenHash(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// keyRecord is what the store knows of an access key: its principal, its
// secret, and what a request signed with it must satisfy.
type keyRecord struct {
	secret    string
	status    string
	tokenHash string
	principal contracts.Principal
	expiresAt int64
}

// loadKey reads the access key with the ID, the root user's included,
// failing with contracts.ErrAccessKeyNotFound when no principal has it.
func (s *Service) loadKey(ctx context.Context, tx *sql.Tx, keyID string) (*keyRecord, error) {
	if keyID == s.root.AccessKeyID {
		return &keyRecord{
			principal: contracts.Principal{
				Kind:        contracts.PrincipalRoot,
				AccountID:   s.root.AccountID,
				ARN:         rootARN(s.root.AccountID),
				UserID:      s.root.AccountID,
				AccessKeyID: keyID,
			},
			secret: s.root.SecretAccessKey,
			status: contracts.StatusActive,
		}, nil
	}

	k := keyRecord{principal: contracts.Principal{AccessKeyID: keyID}}
	p := &k.principal
	var path string
	err := tx.QueryRowContext(ctx,
		`SELECT u.account_id, u.id, u.name, u.path, k.secret, k.status
		 FROM access_keys k JOIN users u ON u.id = k.user_id WHERE k.id = ?`, keyID,
	).Scan(&p.AccountID, &p.UserID, &p.UserName, &path, &k.secret, &k.status)
	switch {
	case err == nil:
		p.Kind = contracts.PrincipalUser
		p.ARN = userARN(p.AccountID, path, p.UserName)
		return &k, nil
	case !errors.Is(err, sql.ErrNoRows):
		return nil, fmt.Errorf("read access key: %w", err)
	}

	var sessionName string
	err = tx.QueryRowContext(ctx,
		`SELECT account_id, session_name, secret, token_sha256, expires_at
		 FROM role_sessions WHERE access_key_id = ?`, keyID,
	).Scan(&p.AccountID, &sessionName, &k.secret, &k.tokenHash, &k.expiresAt)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return nil, contracts.ErrAccessKeyNotFound
	case err != nil:
		return nil, fmt.Errorf("read role session: %w", err)
	}
	p.Kind = contracts.PrincipalRoleSession
	p.ARN = assumedRoleARN(p.AccountID, sessionName)
	p.UserID = roleID(p.AccountID) + ":" + sessionName
	k.status = contracts.StatusActive
	return &k, nil
}

// Principal returns who the access key belongs to, whatever its status, and
// for a role session whether or not it has expired.
func (s *Service) Principal(ctx context.Context, keyID string) (*contracts.Principal, error) {
	var out *contracts.Principal
	err := s.inTx(ctx, func(tx *sql.Tx) error {
		k, err := s.loadKey(ctx, tx, keyID)
		if err != nil {
			return err
		}
		out = &k.principal
		return nil
	})
	return out, err
}

// SigningKey is the store as a sigv4.KeySource: the signing key for scope of
// the root user's key, a user's Active key, or a role session's key with its
// session token, until it expires.
//
// Everything in scope but the access key ID is unauthenticated when it is
// called, since the signature is checked after; so a failure reveals no more
// than AWS's answers do. An unknown key, and a role session's key without its
// token, are sigv4.ErrUnknownAccessKey; a token that is not the key's, or one
// sent with a long-term key, is sigv4.ErrInvalidSessionToken; a role
// session's own token is sigv4.ErrExpiredSessionToken once it expires; and
// an Inactive key is contracts.ErrInactiveAccessKey, which wraps
// sigv4.ErrUnknownAccessKey.
func (s *Service) SigningKey(ctx context.Context, scope sigv4.Scope) (sigv4.Key, error) {
	var k *keyRecord
	err := s.inTx(ctx, func(tx *sql.Tx) error {
		var lErr error
		k, lErr = s.loadKey(ctx, tx, scope.AccessKeyID)
		return lErr
	})
	switch {
	case errors.Is(err, contracts.ErrAccessKeyNotFound):
		return sigv4.Key{}, sigv4.ErrUnknownAccessKey
	case err != nil:
		return sigv4.Key{}, err
	}
	if err = s.checkScope(k, scope); err != nil {
		return sigv4.Key{}, err
	}
	p := k.principal
	return sigv4.Key{
		Principal: sigv4.Principal{
			AccountID: p.AccountID, ARN: p.ARN, AccessKeyID: p.AccessKeyID,
		},
		Signing: sigv4.DeriveSigningKey(k.secret, scope.Date, scope.Region, scope.Service),
	}, nil
}

// checkScope checks the session token scope carries against the key's, and
// the key's status.
func (s *Service) checkScope(k *keyRecord, scope sigv4.Scope) error {
	if k.principal.Kind != contracts.PrincipalRoleSession {
		if scope.SessionToken != "" {
			return sigv4.ErrInvalidSessionToken
		}
		if k.status != contracts.StatusActive {
			return contracts.ErrInactiveAccessKey
		}
		return nil
	}

	switch {
	case scope.SessionToken == "":
		return sigv4.ErrUnknownAccessKey
	case subtle.ConstantTimeCompare([]byte(tokenHash(scope.SessionToken)),
		[]byte(k.tokenHash)) != 1:
		return sigv4.ErrInvalidSessionToken
	case !s.now().Before(unstamp(k.expiresAt)):
		return sigv4.ErrExpiredSessionToken
	}
	return nil
}
