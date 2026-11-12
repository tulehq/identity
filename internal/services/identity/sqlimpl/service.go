// Package sqlimpl implements contracts.IdentityProvider on a SQL database,
// SQLite in practice, reached through gas/database, with its schema applied
// by gas/migrate.
//
// It holds the IAM users of every account, their access keys and the role
// sessions AssumeRole creates, and is the sigv4.KeySource identity verifies
// its own requests against, the root user's configured key included. Each
// operation runs in one transaction.
package sqlimpl

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/gasmod/gas"

	"tule.dev/identity/internal/contracts"
)

// Service stores identities in the database db provides.
type Service struct {
	db         gas.DatabaseProvider
	migrations gas.MigrationManager
	now        func() time.Time
	root       RootSettings
}

var (
	_ contracts.IdentityProvider = (*Service)(nil)
	_ gas.Service                = (*Service)(nil)
)

// NewService returns the constructor gas uses to build a Service whose root
// user is the one root describes, telling the time by now: when keys are
// created and used, and when role sessions expire.
func NewService(root RootSettings, now func() time.Time) func(
	db gas.DatabaseProvider,
	migrations gas.MigrationManager,
) *Service {
	return func(db gas.DatabaseProvider, migrations gas.MigrationManager) *Service {
		return &Service{db: db, migrations: migrations, root: root, now: now}
	}
}

// RootCreateDate returns when the store was created.
func (s *Service) RootCreateDate(ctx context.Context) (time.Time, error) {
	var at int64
	err := s.inTx(ctx, func(tx *sql.Tx) error {
		if err := tx.QueryRowContext(ctx,
			`SELECT created_at FROM store_info`).Scan(&at); err != nil {
			return fmt.Errorf("read the store's creation time: %w", err)
		}
		return nil
	})
	return unstamp(at), err
}

// Name identifies the service to gas.
func (s *Service) Name() string {
	return "tule/services/identity/sql"
}

// Init registers the schema migrations, which gas applies once every service
// is initialized.
func (s *Service) Init(context.Context) error {
	s.migrations.RegisterSlice(s, migrations)
	return nil
}

// Close releases nothing; the database belongs to the database service.
func (s *Service) Close(context.Context) error {
	return nil
}

// inTx runs fn in one transaction, which commits only when fn returns nil.
func (s *Service) inTx(ctx context.Context, fn func(*sql.Tx) error) error {
	if err := s.db.WithTx(ctx, nil, fn); err != nil {
		return fmt.Errorf("%s: %w", s.Name(), err)
	}
	return nil
}

// stamp is how the store keeps a time: Unix seconds, the precision the wire
// carries.
func stamp(t time.Time) int64 {
	return t.Unix()
}

func unstamp(sec int64) time.Time {
	return time.Unix(sec, 0).UTC()
}

// The ARNs of the principals, in the formats of the IAM User Guide.

func rootARN(accountID string) string {
	return "arn:aws:iam::" + accountID + ":root"
}

func userARN(accountID, path, name string) string {
	return "arn:aws:iam::" + accountID + ":user" + path + name
}

func assumedRoleARN(accountID, sessionName string) string {
	return "arn:aws:sts::" + accountID + ":assumed-role/" + contracts.OrganizationRoleName +
		"/" + sessionName
}

// scanner is a row to scan: an *sql.Rows positioned on a row, or an
// *sql.Row.
type scanner interface {
	Scan(dest ...any) error
}

// queryAll runs query in tx and scans every row with scan.
func queryAll[T any](
	ctx context.Context,
	tx *sql.Tx,
	scan func(scanner) (T, error),
	query string,
	args ...any,
) ([]T, error) {
	rows, err := tx.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("query: %w", err)
	}
	// Every error of the iteration is reported by rows.Err below; Close
	// after a full iteration has nothing left to report.
	defer func() { _ = rows.Close() }()

	var out []T
	for rows.Next() {
		v, sErr := scan(rows)
		if sErr != nil {
			return nil, fmt.Errorf("scan: %w", sErr)
		}
		out = append(out, v)
	}
	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("rows: %w", err)
	}
	return out, nil
}

// exists reports whether query, a SELECT 1 ... LIMIT 1, returns a row.
func exists(ctx context.Context, tx *sql.Tx, query string, args ...any) (bool, error) {
	var one int
	err := tx.QueryRowContext(ctx, query, args...).Scan(&one)
	switch {
	case err == nil:
		return true, nil
	case errors.Is(err, sql.ErrNoRows):
		return false, nil
	default:
		return false, fmt.Errorf("query: %w", err)
	}
}

// execCount runs a statement and returns how many rows it changed.
func execCount(ctx context.Context, tx *sql.Tx, query string, args ...any) (int64, error) {
	res, err := tx.ExecContext(ctx, query, args...)
	if err != nil {
		return 0, fmt.Errorf("exec: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("rows affected: %w", err)
	}
	return n, nil
}

func exec(ctx context.Context, tx *sql.Tx, query string, args ...any) error {
	_, err := execCount(ctx, tx, query, args...)
	return err
}
