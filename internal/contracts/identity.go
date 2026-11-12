// Package contracts defines the identity store interface the HTTP modules
// depend on, with its input and output types and sentinel errors, and the
// account directory AssumeRole consults.
package contracts

import (
	"context"
	"errors"
	"time"

	"tule.dev/sigv4"

	"tule.dev/identity/keysource"
)

var (
	// ErrUserNotFound is returned when no user of the account has the
	// name, compared without regard to case.
	ErrUserNotFound = errors.New("identity: user not found")

	// ErrUserExists is returned by CreateUser when a user of the account has
	// the name already, compared without regard to case.
	ErrUserExists = errors.New("identity: user already exists")

	// ErrDeleteConflict is returned by DeleteUser while the IAM user has access
	// keys.
	ErrDeleteConflict = errors.New("identity: user has access keys")

	// ErrAccessKeyNotFound is returned when no access key the operation may
	// act on has the ID.
	ErrAccessKeyNotFound = errors.New("identity: access key not found")

	// ErrAccessKeyLimitExceeded is returned by CreateAccessKey when the
	// user has MaxAccessKeysPerUser keys already.
	ErrAccessKeyLimitExceeded = errors.New("identity: access key limit exceeded")

	// ErrTagLimitExceeded is returned by TagUser when the IAM user would carry
	// more than MaxTagsPerUser tags.
	ErrTagLimitExceeded = errors.New("identity: tag limit exceeded")

	// ErrInvalidMarker is returned for a pagination marker the store did not
	// issue for that listing.
	ErrInvalidMarker = errors.New("identity: invalid marker")

	// ErrInactiveAccessKey is returned by SigningKey for an access key whose
	// status is Inactive. It wraps sigv4.ErrUnknownAccessKey, so a verifier
	// refuses it as AWS refuses an inactive key: as an invalid one.
	ErrInactiveAccessKey = keysource.ErrInactiveAccessKey

	// ErrAccountNotFound is returned by an AccountDirectory for an account
	// that is not a member of the organization, or when there is no
	// organization.
	ErrAccountNotFound = errors.New("identity: account not found")

	// ErrNoAccountDirectory is returned by an AccountDirectory that has no
	// accounts service to ask.
	ErrNoAccountDirectory = errors.New("identity: no accounts endpoint is configured")
)

// MaxAccessKeysPerUser is how many access keys a user may have.
const MaxAccessKeysPerUser = 2

// MaxTagsPerUser is how many tags a user may carry: the most tagListType
// holds.
const MaxTagsPerUser = 50

// The statuses of an access key.
const (
	StatusActive   = "Active"
	StatusInactive = "Inactive"
)

// OrganizationRoleName is the one role a principal can assume: the role
// Organizations creates in each account it creates, under its default name.
const OrganizationRoleName = "OrganizationAccountAccessRole"

// The role session durations, in seconds. AssumeRole takes 900 to 43200 by
// its model, and no more than the role's maximum session duration, which is
// one hour for a role created with no other setting; the default is one
// hour.
const (
	MinSessionDuration     = 900
	MaxSessionDuration     = 43200
	RoleMaxSessionDuration = 3600
	DefaultSessionDuration = 3600
)

// User is an IAM user. Tags is only set by GetUser.
type User struct {
	CreateDate time.Time
	AccountID  string
	ID         string
	Name       string
	Path       string
	ARN        string
	Tags       []Tag
}

// Tag is a tag on a user. Keys are unique on a user without regard to case,
// and keep the case they were last set with.
type Tag struct {
	Key   string
	Value string
}

// AccessKey is a user's long-term access key. SecretAccessKey is only set by
// CreateAccessKey.
type AccessKey struct {
	CreateDate      time.Time
	ID              string
	UserName        string
	Status          string
	SecretAccessKey string
}

// KeyLastUsed is when, with what service and in what region an access key
// was last used. LastUsed is the zero time for a key never used. UserName
// is empty for the root user's key.
type KeyLastUsed struct {
	LastUsed time.Time
	UserName string
	Service  string
	Region   string
}

// PrincipalKind is the kind of principal an access key belongs to.
type PrincipalKind int

// The principal kinds.
const (
	// PrincipalRoot is the management account's root user, the configured
	// access key.
	PrincipalRoot PrincipalKind = iota + 1
	// PrincipalUser is an IAM user.
	PrincipalUser
	// PrincipalRoleSession is a session of OrganizationRoleName.
	PrincipalRoleSession
)

// Principal is who an access key belongs to. UserID is the aws:userid of the
// principal: the account ID for the root user, the IAM user's ID for a user,
// and the role ID and session name for a role session. UserName is the
// user's name, for a user.
type Principal struct {
	AccountID   string
	ARN         string
	UserID      string
	UserName    string
	AccessKeyID string
	Kind        PrincipalKind
}

// Page is one page of a listing. Marker resumes the listing after it, and is
// empty on the last page.
type Page[T any] struct {
	Marker string
	Items  []T
}

// ListUsersInput selects the users ListUsers returns: those of the account
// whose path starts with PathPrefix, a page of up to MaxItems after Marker.
type ListUsersInput struct {
	AccountID  string
	PathPrefix string
	Marker     string
	MaxItems   int
}

// ListAccessKeysInput selects the keys ListAccessKeys returns: those of the
// user, a page of up to MaxItems after Marker.
type ListAccessKeysInput struct {
	AccountID string
	UserName  string
	Marker    string
	MaxItems  int
}

// ListUserTagsInput selects the tags ListUserTags returns: those of the
// user, a page of up to MaxItems after Marker.
type ListUserTagsInput struct {
	AccountID string
	UserName  string
	Marker    string
	MaxItems  int
}

// CreateRoleSessionInput describes a session of OrganizationRoleName in an
// account.
type CreateRoleSessionInput struct {
	AccountID   string
	SessionName string
	Duration    time.Duration
}

// RoleSession is a new role session and its temporary credentials.
type RoleSession struct {
	Expiration      time.Time
	AccessKeyID     string
	SecretAccessKey string
	SessionToken    string
	ARN             string
	AssumedRoleID   string
}

// IdentityProvider is the identity store: users, their access keys and role
// sessions, and the signing keys of all of them. Every user and key belongs
// to one account, and the operations act in the account they are given.
type IdentityProvider interface {
	sigv4.KeySource

	CreateUser(ctx context.Context, accountID, name, path string, tags []Tag) (*User, error)
	GetUser(ctx context.Context, accountID, name string) (*User, error)
	ListUsers(ctx context.Context, in ListUsersInput) (*Page[User], error)
	DeleteUser(ctx context.Context, accountID, name string) error

	// TagUser sets tags on the IAM user, replacing a tag whose key it has
	// already, compared without regard to case.
	TagUser(ctx context.Context, accountID, userName string, tags []Tag) error
	// UntagUser removes the tags with the keys from the IAM user, compared
	// without regard to case. A key the IAM user has no tag with is not an
	// error.
	UntagUser(ctx context.Context, accountID, userName string, keys []string) error
	// ListUserTags lists the IAM user's tags in order of their keys.
	ListUserTags(ctx context.Context, in ListUserTagsInput) (*Page[Tag], error)

	// RootCreateDate is when the root user is reported created, and its
	// access key: when the store was created, since neither is stored.
	RootCreateDate(ctx context.Context) (time.Time, error)

	CreateAccessKey(ctx context.Context, accountID, userName string) (*AccessKey, error)
	ListAccessKeys(ctx context.Context, in ListAccessKeysInput) (*Page[AccessKey], error)
	UpdateAccessKey(ctx context.Context, accountID, userName, keyID, status string) error
	DeleteAccessKey(ctx context.Context, accountID, userName, keyID string) error

	// GetAccessKeyLastUsed reports the last use of a long-term key of the
	// account: a user's, or the root user's.
	GetAccessKeyLastUsed(ctx context.Context, accountID, keyID string) (*KeyLastUsed, error)

	// RecordKeyUse records that a long-term access key was used now, with
	// service in region. It records nothing for a role session's key.
	RecordKeyUse(ctx context.Context, keyID, service, region string) error

	CreateRoleSession(ctx context.Context, in CreateRoleSessionInput) (*RoleSession, error)

	// Principal returns who an access key belongs to, whatever its status,
	// or ErrAccessKeyNotFound.
	Principal(ctx context.Context, keyID string) (*Principal, error)
}

// AccountDirectory tells which account manages the organization and whether
// an account is an active member of it.
type AccountDirectory interface {
	// ManagementAccountID returns the organization's management account. It
	// returns ErrAccountNotFound when there is no organization, and
	// ErrNoAccountDirectory when there is no accounts service to ask.
	ManagementAccountID(ctx context.Context) (string, error)

	// IsActiveMember reports whether accountID is a member of the
	// organization in the ACTIVE state. It returns ErrAccountNotFound for an
	// account that is not a member, and ErrNoAccountDirectory when there is
	// no accounts service to ask.
	IsActiveMember(ctx context.Context, accountID string) (bool, error)
}
