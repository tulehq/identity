package sqlimpl

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"regexp"
	"testing"
	"time"

	"github.com/gasmod/gas"
	"github.com/gasmod/gas/database"
	"github.com/gasmod/gas/migrate"
	_ "modernc.org/sqlite"
	"tule.dev/sigv4"

	"tule.dev/identity/internal/contracts"
)

const (
	management = "000000000000"
	member     = "123456789012"
	rootKeyID  = "AKIAIOSFODNN7EXAMPLE"
	rootSecret = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
)

// newStore opens a store on a fresh database file the way the app wires it:
// gas/database, then gas/migrate applying the schema the store registers.
func newStore(t *testing.T) *Service {
	t.Helper()
	ctx := context.Background()
	logger := &gas.NopLogger{}

	cfg := database.DefaultConfig()
	cfg.Database.Dialect = database.DialectSQLite
	cfg.Database.DSN = gas.Secret("file:" + filepath.Join(t.TempDir(), "identity.db"))
	cfg.Database.MaxOpenConns = 1
	cfg.Database.MaxIdleConns = 1

	db, err := database.New(database.WithConfig(cfg))(nil, logger)
	check(t, err == nil, "new database: %v", err)
	if err = db.Init(ctx); err != nil {
		t.Fatalf("init database: %v", err)
	}
	t.Cleanup(func() {
		if cErr := db.Close(ctx); cErr != nil {
			t.Errorf("close database: %v", cErr)
		}
	})

	mm, err := migrate.New()(db, logger)
	check(t, err == nil, "new migrate: %v", err)
	if err = mm.Init(ctx); err != nil {
		t.Fatalf("init migrate: %v", err)
	}

	s := NewService(RootSettings{
		AccessKeyID: rootKeyID, SecretAccessKey: rootSecret, AccountID: management,
	}, time.Now)(db, mm)
	if err = s.Init(ctx); err != nil {
		t.Fatalf("init store: %v", err)
	}
	if err = mm.RunPendingContext(ctx); err != nil {
		t.Fatalf("run migrations: %v", err)
	}
	return s
}

func requireErr(t *testing.T, err, want error) {
	t.Helper()
	check(t, errors.Is(err, want), "got %v, want %v", err, want)
}

// check fails the test with the message unless ok.
func check(t *testing.T, ok bool, format string, args ...any) {
	t.Helper()
	if !ok {
		t.Fatalf(format, args...)
	}
}

func requireNoErr(t *testing.T, err error, what string) {
	t.Helper()
	check(t, err == nil, "%s: %v", what, err)
}

var (
	userIDPattern    = regexp.MustCompile(`^AIDA[A-Z2-7]{17}$`)
	accessKeyPattern = regexp.MustCompile(`^AKIA[A-Z2-7]{16}$`)
	sessionPattern   = regexp.MustCompile(`^ASIA[A-Z2-7]{16}$`)
	roleIDPattern    = regexp.MustCompile(`^AROA[A-Z2-7]{17}:e2e$`)
	secretPattern    = regexp.MustCompile(`^[A-Za-z0-9+/]{40}$`)
)

func TestUsersAreUniquePerAccountWithoutRegardToCase(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)

	u, err := s.CreateUser(ctx, management, "Dev", "/team/", nil)
	requireNoErr(t, err, "create user")
	check(
		t,
		userIDPattern.MatchString(u.ID) &&
			u.ARN == "arn:aws:iam::000000000000:user/team/Dev",
		"user = %+v",
		u,
	)

	_, err = s.CreateUser(ctx, management, "dev", "/", nil)
	requireErr(t, err, contracts.ErrUserExists)

	// Another account may have the name.
	_, err = s.CreateUser(ctx, member, "dev", "/", nil)
	requireNoErr(t, err, "create user in another account")

	got, err := s.GetUser(ctx, management, "DEV")
	requireNoErr(t, err, "get user")
	check(
		t,
		got.ID == u.ID &&
			got.Name == "Dev" &&
			got.CreateDate.Equal(u.CreateDate),
		"got %+v, want %+v",
		got,
		u,
	)

	_, err = s.GetUser(ctx, member, "Dev2")
	requireErr(t, err, contracts.ErrUserNotFound)
}

func TestListUsersPagesByNameAndFiltersByPath(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)
	for _, u := range []struct{ name, path string }{
		{"carol", "/a/"}, {"Bob", "/a/b/"}, {"alice", "/"}, {"dave", "/A/"},
	} {
		_, err := s.CreateUser(ctx, management, u.name, u.path, nil)
		requireNoErr(t, err, "create user "+u.name)
	}
	_, err := s.CreateUser(ctx, member, "erin", "/", nil)
	requireNoErr(t, err, "create user in another account")

	var names []string
	in := contracts.ListUsersInput{AccountID: management, PathPrefix: "/", MaxItems: 1}
	for pages := 0; ; pages++ {
		if pages > 10 {
			t.Fatal("pagination did not end")
		}
		page, lErr := s.ListUsers(ctx, in)
		requireNoErr(t, lErr, "list users")
		for _, u := range page.Items {
			names = append(names, u.Name)
		}
		if page.Marker == "" {
			break
		}
		in.Marker = page.Marker
	}
	check(t, fmt.Sprint(names) == "[alice Bob carol dave]", "names = %v", names)

	// The prefix is matched exactly: with case, and with no wildcards.
	page, err := s.ListUsers(ctx, contracts.ListUsersInput{
		AccountID: management, PathPrefix: "/a/", MaxItems: 10,
	})
	requireNoErr(t, err, "list users under /a/")
	check(
		t,
		len(page.Items) == 2 &&
			page.Items[0].Name == "Bob" &&
			page.Items[1].Name == "carol",
		"users under /a/ = %+v",
		page.Items,
	)
}

func TestAMarkerOnlyResumesItsListing(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)
	for _, name := range []string{"alice", "bob"} {
		_, err := s.CreateUser(ctx, management, name, "/", nil)
		requireNoErr(t, err, "create user "+name)
	}

	first, err := s.ListUsers(ctx, contracts.ListUsersInput{
		AccountID: management, PathPrefix: "/", MaxItems: 1,
	})
	requireNoErr(t, err, "list first page")
	for name, in := range map[string]contracts.ListUsersInput{
		"other prefix":  {AccountID: management, PathPrefix: "/a/", Marker: first.Marker},
		"other account": {AccountID: member, PathPrefix: "/", Marker: first.Marker},
		"not a marker":  {AccountID: management, PathPrefix: "/", Marker: "garbage!"},
	} {
		in.MaxItems = 10
		_, err = s.ListUsers(ctx, in)
		check(
			t,
			errors.Is(err, contracts.ErrInvalidMarker),
			"%s: got %v, want ErrInvalidMarker",
			name,
			err,
		)
	}
}

func TestAccessKeysOfAUser(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)
	_, err := s.CreateUser(ctx, management, "dev", "/", nil)
	requireNoErr(t, err, "create user")

	k1, err := s.CreateAccessKey(ctx, management, "dev")
	requireNoErr(t, err, "create first key")
	check(
		t,
		accessKeyPattern.MatchString(k1.ID) &&
			secretPattern.MatchString(k1.SecretAccessKey) &&
			k1.Status == contracts.StatusActive,
		"key = %+v",
		k1,
	)
	k2, err := s.CreateAccessKey(ctx, management, "DEV")
	requireNoErr(t, err, "create second key")
	_, err = s.CreateAccessKey(ctx, management, "dev")
	requireErr(t, err, contracts.ErrAccessKeyLimitExceeded)

	page, err := s.ListAccessKeys(ctx, contracts.ListAccessKeysInput{
		AccountID: management, UserName: "dev", MaxItems: 1,
	})
	requireNoErr(t, err, "list first page")
	check(
		t,
		len(page.Items) == 1 &&
			page.Items[0].ID == k1.ID &&
			page.Items[0].SecretAccessKey == "" &&
			page.Marker != "",
		"first page = %+v",
		page,
	)
	page, err = s.ListAccessKeys(ctx, contracts.ListAccessKeysInput{
		AccountID: management, UserName: "dev", MaxItems: 1, Marker: page.Marker,
	})
	requireNoErr(t, err, "list second page")
	check(
		t,
		len(page.Items) == 1 &&
			page.Items[0].ID == k2.ID &&
			page.Marker == "",
		"second page = %+v",
		page,
	)

	requireErr(t, s.DeleteUser(ctx, management, "dev"), contracts.ErrDeleteConflict)

	// A key is only found through its own user, in its own account.
	_, err = s.CreateUser(ctx, management, "other", "/", nil)
	requireNoErr(t, err, "create other user")
	requireErr(t, s.UpdateAccessKey(ctx, management, "other", k1.ID, contracts.StatusInactive),
		contracts.ErrAccessKeyNotFound)
	requireErr(t, s.DeleteAccessKey(ctx, member, "dev", k1.ID), contracts.ErrUserNotFound)

	requireNoErr(t, s.UpdateAccessKey(ctx, management, "dev", k1.ID, contracts.StatusInactive),
		"deactivate key")
	requireNoErr(t, s.DeleteAccessKey(ctx, management, "dev", k1.ID), "delete first key")
	requireNoErr(t, s.DeleteAccessKey(ctx, management, "dev", k2.ID), "delete second key")
	requireErr(t, s.DeleteAccessKey(ctx, management, "dev", k2.ID), contracts.ErrAccessKeyNotFound)
	requireNoErr(t, s.DeleteUser(ctx, management, "dev"), "delete user")
}

func TestKeyLastUse(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)
	at := time.Date(2026, 11, 13, 10, 0, 0, 0, time.UTC)
	s.now = func() time.Time { return at }

	_, err := s.CreateUser(ctx, management, "dev", "/", nil)
	requireNoErr(t, err, "create user")
	k, err := s.CreateAccessKey(ctx, management, "dev")
	requireNoErr(t, err, "create key")

	used, err := s.GetAccessKeyLastUsed(ctx, management, k.ID)
	requireNoErr(t, err, "last use of a new key")
	check(
		t,
		used.LastUsed.IsZero() &&
			used.UserName == "dev" &&
			used.Service == "",
		"new key's last use = %+v",
		used,
	)

	requireNoErr(t, s.RecordKeyUse(ctx, k.ID, "s3", "eu-west-1"), "record use")
	used, err = s.GetAccessKeyLastUsed(ctx, management, k.ID)
	requireNoErr(t, err, "last use")
	check(
		t,
		used.LastUsed.Equal(at) &&
			used.Service == "s3" &&
			used.Region == "eu-west-1",
		"last use = %+v",
		used,
	)

	// The root user's key is the management account's and has no user.
	requireNoErr(t, s.RecordKeyUse(ctx, rootKeyID, "iam", "us-east-1"), "record root use")
	used, err = s.GetAccessKeyLastUsed(ctx, management, rootKeyID)
	requireNoErr(t, err, "root key's last use")
	check(t, used.UserName == "" && used.Service == "iam", "root key's last use = %+v", used)

	_, err = s.GetAccessKeyLastUsed(ctx, member, k.ID)
	requireErr(t, err, contracts.ErrAccessKeyNotFound)
	_, err = s.GetAccessKeyLastUsed(ctx, member, rootKeyID)
	requireErr(t, err, contracts.ErrAccessKeyNotFound)

	// A deleted key's use goes with it.
	requireNoErr(t, s.DeleteAccessKey(ctx, management, "dev", k.ID), "delete key")
	_, err = s.GetAccessKeyLastUsed(ctx, management, k.ID)
	requireErr(t, err, contracts.ErrAccessKeyNotFound)
}

func scopeOf(keyID, token string) sigv4.Scope {
	return sigv4.Scope{
		AccessKeyID: keyID, SessionToken: token,
		Date: "20261113", Region: "us-east-1", Service: "sts",
	}
}

func TestSigningKeys(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)
	_, err := s.CreateUser(ctx, management, "dev", "/", nil)
	requireNoErr(t, err, "create user")
	k, err := s.CreateAccessKey(ctx, management, "dev")
	requireNoErr(t, err, "create key")

	key, err := s.SigningKey(ctx, scopeOf(rootKeyID, ""))
	requireNoErr(t, err, "root key")
	check(
		t,
		string(key.Signing) == string(sigv4.DeriveSigningKey(rootSecret, "20261113", "us-east-1", "sts")) &&
			key.Principal.ARN == "arn:aws:iam::000000000000:root",
		"root key = %+v",
		key,
	)

	key, err = s.SigningKey(ctx, scopeOf(k.ID, ""))
	requireNoErr(t, err, "user key")
	check(
		t,
		string(key.Signing) == string(sigv4.DeriveSigningKey(k.SecretAccessKey, "20261113", "us-east-1", "sts")) &&
			key.Principal.ARN == "arn:aws:iam::000000000000:user/dev",
		"user key = %+v",
		key,
	)

	_, err = s.SigningKey(ctx, scopeOf(k.ID, "token"))
	requireErr(t, err, sigv4.ErrInvalidSessionToken)
	_, err = s.SigningKey(ctx, scopeOf(rootKeyID, "token"))
	requireErr(t, err, sigv4.ErrInvalidSessionToken)
	_, err = s.SigningKey(ctx, scopeOf("AKIAAAAAAAAAAAAAAAAA", ""))
	requireErr(t, err, sigv4.ErrUnknownAccessKey)

	requireNoErr(t, s.UpdateAccessKey(ctx, management, "dev", k.ID, contracts.StatusInactive),
		"deactivate key")
	_, err = s.SigningKey(ctx, scopeOf(k.ID, ""))
	requireErr(t, err, contracts.ErrInactiveAccessKey)
	requireErr(t, err, sigv4.ErrUnknownAccessKey)
}

// organizationRole is OrganizationAccountAccessRole of the member account.
func organizationRole(t *testing.T, s *Service) *contracts.Role {
	t.Helper()
	ctx := context.Background()
	r, err := s.CreateOrganizationRole(ctx, member, management)
	if errors.Is(err, contracts.ErrOrganizationRoleCreated) {
		r, err = s.GetRole(ctx, member, contracts.OrganizationRoleName)
	}
	requireNoErr(t, err, "the organization role")
	return r
}

func TestRoleSessions(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)
	at := time.Date(2026, 11, 13, 10, 0, 0, 0, time.UTC)
	s.now = func() time.Time { return at }
	role := organizationRole(t, s)

	rs, err := s.CreateRoleSession(ctx, contracts.CreateRoleSessionInput{
		Role: role, SessionName: "e2e", Duration: 15 * time.Minute,
	})
	requireNoErr(t, err, "create role session")
	check(
		t,
		sessionPattern.MatchString(rs.AccessKeyID) &&
			roleIDPattern.MatchString(rs.AssumedRoleID) &&
			secretPattern.MatchString(rs.SecretAccessKey) &&
			rs.SessionToken != "" &&
			rs.Expiration.Equal(at.Add(15*time.Minute)) &&
			rs.ARN == "arn:aws:sts::123456789012:assumed-role/OrganizationAccountAccessRole/e2e",
		"session = %+v",
		rs,
	)

	// The role's ID is the role's, the same in every session.
	again, err := s.CreateRoleSession(ctx, contracts.CreateRoleSessionInput{
		Role: role, SessionName: "e2e", Duration: time.Hour,
	})
	requireNoErr(t, err, "create second session")
	check(
		t,
		again.AssumedRoleID == rs.AssumedRoleID &&
			again.AccessKeyID != rs.AccessKeyID,
		"second session = %+v, first %+v",
		again,
		rs,
	)

	key, err := s.SigningKey(ctx, scopeOf(rs.AccessKeyID, rs.SessionToken))
	requireNoErr(t, err, "session key")
	check(
		t,
		key.Principal.AccountID == member &&
			key.Principal.ARN == rs.ARN,
		"session key = %+v",
		key,
	)

	_, err = s.SigningKey(ctx, scopeOf(rs.AccessKeyID, ""))
	requireErr(t, err, sigv4.ErrUnknownAccessKey)
	_, err = s.SigningKey(ctx, scopeOf(rs.AccessKeyID, again.SessionToken))
	requireErr(t, err, sigv4.ErrInvalidSessionToken)

	p, err := s.Principal(ctx, rs.AccessKeyID)
	requireNoErr(t, err, "session principal")
	check(
		t,
		p.Kind == contracts.PrincipalRoleSession &&
			p.UserID == rs.AssumedRoleID,
		"principal = %+v",
		p,
	)
}

func TestARoleSessionExpires(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)
	at := time.Date(2026, 11, 13, 10, 0, 0, 0, time.UTC)
	s.now = func() time.Time { return at }
	role := organizationRole(t, s)
	var sessions [2]*contracts.RoleSession
	for i := range sessions {
		rs, err := s.CreateRoleSession(ctx, contracts.CreateRoleSessionInput{
			Role: role, SessionName: "e2e", Duration: 15 * time.Minute,
		})
		requireNoErr(t, err, "create role session")
		sessions[i] = rs
	}
	rs, again := sessions[0], sessions[1]

	// At its expiration the session's own token is expired; another token is
	// still only invalid, so expiry tells nothing about a wrong token.
	s.now = func() time.Time { return rs.Expiration }
	_, err := s.SigningKey(ctx, scopeOf(rs.AccessKeyID, rs.SessionToken))
	requireErr(t, err, sigv4.ErrExpiredSessionToken)
	_, err = s.SigningKey(ctx, scopeOf(rs.AccessKeyID, again.SessionToken))
	requireErr(t, err, sigv4.ErrInvalidSessionToken)

	// Its use is not recorded: GetAccessKeyLastUsed knows long-term keys.
	requireNoErr(t, s.RecordKeyUse(ctx, rs.AccessKeyID, "sts", "us-east-1"), "record use")
	_, err = s.GetAccessKeyLastUsed(ctx, member, rs.AccessKeyID)
	requireErr(t, err, contracts.ErrAccessKeyNotFound)
}
