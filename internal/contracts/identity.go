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

	// ErrHasAttachedPolicies is returned by DeleteUser and DeleteRole while
	// the entity has managed policies attached.
	ErrHasAttachedPolicies = errors.New("identity: entity has attached policies")

	// ErrHasInlinePolicies is returned by DeleteUser and DeleteRole while the
	// entity has inline policies.
	ErrHasInlinePolicies = errors.New("identity: entity has inline policies")

	// ErrOrganizationRoleCreated is returned by CreateOrganizationRole for a
	// member account OrganizationRoleName was created in before.
	ErrOrganizationRoleCreated = errors.New("identity: the organization role was created before")

	// ErrRoleNotFound is returned when no role of the account has the name,
	// compared without regard to case.
	ErrRoleNotFound = errors.New("identity: role not found")

	// ErrRoleExists is returned by CreateRole when a role of the account has
	// the name already, compared without regard to case.
	ErrRoleExists = errors.New("identity: role already exists")

	// ErrPolicyNotFound is returned when no managed policy the account can
	// see has the ARN.
	ErrPolicyNotFound = errors.New("identity: policy not found")

	// ErrPolicyExists is returned by CreatePolicy when a managed policy of
	// the account has the name already.
	ErrPolicyExists = errors.New("identity: policy already exists")

	// ErrPolicyVersionNotFound is returned when the managed policy has no
	// version with the ID.
	ErrPolicyVersionNotFound = errors.New("identity: policy version not found")

	// ErrPolicyAttached is returned by DeletePolicy while the policy is
	// attached to a user or role.
	ErrPolicyAttached = errors.New("identity: policy is attached")

	// ErrPolicyHasVersions is returned by DeletePolicy while the policy has
	// versions other than its default one.
	ErrPolicyHasVersions = errors.New("identity: policy has non-default versions")

	// ErrDefaultPolicyVersion is returned by DeletePolicyVersion for the
	// policy's default version.
	ErrDefaultPolicyVersion = errors.New("identity: cannot delete the default version")

	// ErrPolicyVersionLimitExceeded is returned by CreatePolicyVersion when
	// the policy has MaxPolicyVersions versions already.
	ErrPolicyVersionLimitExceeded = errors.New("identity: policy version limit exceeded")

	// ErrAttachedPolicyLimitExceeded is returned by AttachPolicy when the
	// entity has its kind's quota of managed policies attached already.
	ErrAttachedPolicyLimitExceeded = errors.New("identity: attached policy limit exceeded")

	// ErrInlinePolicySizeExceeded is returned by PutInlinePolicy when the
	// entity's inline policies would exceed its kind's aggregate size.
	ErrInlinePolicySizeExceeded = errors.New("identity: inline policy size exceeded")

	// ErrInlinePolicyNotFound is returned when the entity has no inline
	// policy with the name.
	ErrInlinePolicyNotFound = errors.New("identity: inline policy not found")

	// ErrPolicyNotAttached is returned by DetachPolicy for a policy the
	// entity does not have attached.
	ErrPolicyNotAttached = errors.New("identity: policy not attached")

	// ErrAWSManagedPolicy is returned for a change to an AWS managed policy,
	// which only AWS can change.
	ErrAWSManagedPolicy = errors.New("identity: AWS managed policies cannot be changed")

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

// OrganizationRoleName is the role Organizations creates in each account it
// creates, under its default name. Identity creates it in a member account
// the first time the management account assumes it there.
const OrganizationRoleName = "OrganizationAccountAccessRole"

// AdministratorAccessARN is the AWS managed policy every account can attach
// that allows every action on every resource. OrganizationRoleName has it
// attached.
const AdministratorAccessARN = "arn:aws:iam::aws:policy/AdministratorAccess"

// AWSAccount is the account part of an AWS managed policy's ARN.
const AWSAccount = "aws"

// The IAM quotas this service applies (the IAM User Guide, IAM and STS
// quotas, at their default values). Policy sizes count characters, white
// space excluded.
const (
	MaxPolicyVersions         = 5
	MaxManagedPoliciesPerUser = 10
	MaxManagedPoliciesPerRole = 20
	MaxManagedPolicySize      = 6144
	MaxUserInlinePolicySize   = 2048
	MaxRoleInlinePolicySize   = 10240
	MaxRoleTrustPolicySize    = 2048
)

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
	// PrincipalRoleSession is a session of a role.
	PrincipalRoleSession
)

// Principal is who an access key belongs to. UserID is the aws:userid of the
// principal: the account ID for the root user, the IAM user's ID for a user,
// and the role ID and session name for a role session. UserName is the
// user's name, for a user. RoleARN is the ARN of a role session's role, its
// aws:PrincipalArn, with the role's path.
//
// A session is bound to its role's unique ID, as AWS binds a role to its ID
// rather than its name. Orphaned marks a session whose role no longer
// exists, though another role may since have taken its name: it has no
// role, so no RoleARN and no policies.
type Principal struct {
	AccountID   string
	ARN         string
	UserID      string
	UserName    string
	RoleARN     string
	AccessKeyID string
	Kind        PrincipalKind
	Orphaned    bool
}

// PrincipalARN is the aws:PrincipalArn of p: a role session's role, empty
// for an orphaned session, or the ARN p signs as.
func (p *Principal) PrincipalARN() string {
	if p.Kind == PrincipalRoleSession {
		return p.RoleARN
	}
	return p.ARN
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

// CreateRoleSessionInput describes a session of a role.
type CreateRoleSessionInput struct {
	Role        *Role
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

	// CreatePolicy creates a customer managed policy, failing with
	// ErrPolicyExists when the account has one with the name.
	CreatePolicy(ctx context.Context, in CreatePolicyInput) (*ManagedPolicy, error)
	// GetPolicy returns the managed policy with the ARN, with its tags: the
	// account's own, or an AWS managed one.
	GetPolicy(ctx context.Context, accountID, arn string) (*ManagedPolicy, error)
	ListPolicies(ctx context.Context, in ListPoliciesInput) (*Page[ManagedPolicy], error)
	// DeletePolicy deletes a customer managed policy, failing with
	// ErrPolicyAttached while it is attached and ErrPolicyHasVersions while
	// it has versions besides its default.
	DeletePolicy(ctx context.Context, accountID, arn string) error
	// CreatePolicyVersion adds a version to a customer managed policy,
	// failing with ErrPolicyVersionLimitExceeded when it has
	// MaxPolicyVersions already.
	CreatePolicyVersion(
		ctx context.Context, accountID, arn, document string, setAsDefault bool,
	) (*PolicyVersion, error)
	GetPolicyVersion(ctx context.Context, accountID, arn, versionID string) (*PolicyVersion, error)
	ListPolicyVersions(
		ctx context.Context, in ListPolicyVersionsInput,
	) (*Page[PolicyVersion], error)
	// DeletePolicyVersion deletes a version other than the default, which is
	// ErrDefaultPolicyVersion.
	DeletePolicyVersion(ctx context.Context, accountID, arn, versionID string) error
	SetDefaultPolicyVersion(ctx context.Context, accountID, arn, versionID string) error

	// AttachPolicy attaches a managed policy to the entity. Attaching one it
	// has attached already changes nothing.
	AttachPolicy(ctx context.Context, e Entity, arn string) error
	DetachPolicy(ctx context.Context, e Entity, arn string) error
	ListAttachedPolicies(
		ctx context.Context, in ListAttachedPoliciesInput,
	) (*Page[AttachedPolicy], error)
	// PutInlinePolicy embeds the policy in the entity, replacing one of the
	// same name.
	PutInlinePolicy(ctx context.Context, e Entity, name, document string) error
	GetInlinePolicy(ctx context.Context, e Entity, name string) (*InlinePolicy, error)
	ListInlinePolicies(ctx context.Context, in ListInlinePoliciesInput) (*Page[string], error)
	DeleteInlinePolicy(ctx context.Context, e Entity, name string) error

	// CreateRole creates a role, binding the IAM user and role ARNs its trust
	// policy names to their unique IDs. One that no user or role has is an
	// *InvalidPrincipalError.
	CreateRole(ctx context.Context, in CreateRoleInput) (*Role, error)
	// GetRole returns the role of the account with the name, compared
	// without regard to case, with its tags.
	GetRole(ctx context.Context, accountID, name string) (*Role, error)
	ListRoles(ctx context.Context, in ListRolesInput) (*Page[Role], error)
	// AllRoles returns every role of every account, with its trust policy
	// as stored, in order of account and name, without its trust bindings
	// or tags.
	AllRoles(ctx context.Context) ([]Role, error)
	UpdateRole(ctx context.Context, in UpdateRoleInput) error
	// UpdateAssumeRolePolicy replaces the role's trust policy, binding the
	// user and role ARNs it names, principals, to their unique IDs.
	UpdateAssumeRolePolicy(
		ctx context.Context, accountID, name, document string, principals []string,
	) error
	// DeleteRole deletes the role, failing with ErrHasAttachedPolicies or
	// ErrHasInlinePolicies while it has policies.
	DeleteRole(ctx context.Context, accountID, name string) error
	// OrganizationRoleCreated reports whether OrganizationRoleName has been
	// created in the member account, which happens once, the first time the
	// management account assumes it there. A role the member account deleted
	// since stays deleted.
	OrganizationRoleCreated(ctx context.Context, accountID string) (bool, error)
	// CreateOrganizationRole creates OrganizationRoleName in the member
	// account, with AdministratorAccess attached and a trust policy for
	// managementAccountID, and records that it was created. Once it has
	// been, it creates nothing and returns ErrOrganizationRoleCreated.
	CreateOrganizationRole(
		ctx context.Context,
		accountID, managementAccountID string,
	) (*Role, error)

	// EffectivePolicies returns the identity policy documents in effect for
	// the principal the access key belongs to: a user's or a role session's
	// role's inline policies and the default versions of its attached
	// managed policies. The root user has none, as it is never evaluated.
	EffectivePolicies(ctx context.Context, p *Principal) ([]string, error)

	// Principal returns who an access key belongs to, whatever its status,
	// or ErrAccessKeyNotFound.
	Principal(ctx context.Context, keyID string) (*Principal, error)

	// PrincipalIDs returns the unique ID of the IAM user or role each user or
	// role ARN names, its path and name compared with their case, keyed by
	// the ARN; an ARN no user or role has is left out.
	PrincipalIDs(ctx context.Context, arns []string) (map[string]string, error)
	// PrincipalARNs returns the current ARN of the IAM user or role each unique
	// ID belongs to, keyed by the ID; an ID no user or role has is left
	// out.
	PrincipalARNs(ctx context.Context, ids []string) (map[string]string, error)
}

// Organization is where an account sits in the organization: the values
// of aws:PrincipalOrgID and aws:PrincipalOrgPaths for its principals. The
// zero value is an account outside the organization, whose principals have
// neither key.
type Organization struct {
	// ID is the organization's ID, o-xxxxxxxxxx.
	ID string
	// Path is the account's path, the organization ID, the root ID and the
	// IDs of the organizational units down to the account's parent, each
	// followed by a slash: o-a1b2c3d4e5/r-ab12/ou-ab12-11111111/.
	Path string
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

	// OrganizationOf returns where accountID sits in the organization: the
	// organization's ID and the account's path, for an ACTIVE member or the
	// management account, and the zero Organization for any other account
	// or when there is no organization. It returns ErrNoAccountDirectory
	// when there is no accounts service to ask.
	OrganizationOf(ctx context.Context, accountID string) (Organization, error)
}
