package contracts

import (
	"strings"
	"time"
	"unicode/utf8"
)

// EntityKind is the kind of IAM identity policies attach to.
type EntityKind string

// The entity kinds.
const (
	EntityUser EntityKind = "user"
	EntityRole EntityKind = "role"
)

// Entity names the IAM user or role of an account a policy operation acts
// on. Name is compared without regard to case.
type Entity struct {
	Kind      EntityKind
	AccountID string
	Name      string
}

// ManagedPolicy is a managed policy: a customer managed policy of an
// account, or an AWS managed one, whose AccountID is AWSAccount.
// AttachmentCount counts the users and roles of the account asking that have
// it attached. Tags is only set by CreatePolicy and GetPolicy.
type ManagedPolicy struct {
	CreateDate       time.Time
	UpdateDate       time.Time
	AccountID        string
	ID               string
	Name             string
	Path             string
	ARN              string
	Description      string
	DefaultVersionID string
	Tags             []Tag
	AttachmentCount  int
}

// PolicyVersion is a version of a managed policy. Document is only set by
// GetPolicyVersion.
type PolicyVersion struct {
	CreateDate time.Time
	VersionID  string
	Document   string
	IsDefault  bool
}

// AttachedPolicy is a managed policy attached to a user or role.
type AttachedPolicy struct {
	Name string
	ARN  string
}

// InlinePolicy is a policy embedded in a user or role.
type InlinePolicy struct {
	Name     string
	Document string
}

// Role is an IAM role. Tags is only set by CreateRole and GetRole.
// TrustPolicy is the trust policy as it was saved; TrustBindings are the
// user and role ARNs its Principal elements name, each bound to the unique
// ID of the user or role that had the ARN when the policy was saved.
type Role struct {
	CreateDate         time.Time
	AccountID          string
	ID                 string
	Name               string
	Path               string
	ARN                string
	TrustPolicy        string
	Description        string
	Tags               []Tag
	TrustBindings      []TrustBinding
	MaxSessionDuration int
}

// TrustBinding is a user or role ARN a trust policy names, bound to the
// unique ID of the user or role it named when the policy was saved, as IAM
// binds it ("AWS JSON policy elements: Principal", IAM role principals and
// IAM user principals). Current is false once no user or role has that ID:
// it was deleted, and a user or role created again with its ARN is another
// principal, which the trust policy does not name.
type TrustBinding struct {
	ARN         string
	PrincipalID string
	Current     bool
}

// BindingFor returns the binding of the ARN, or nil when the trust policy
// was saved without one for it.
func (r *Role) BindingFor(arn string) *TrustBinding {
	for i := range r.TrustBindings {
		if r.TrustBindings[i].ARN == arn {
			return &r.TrustBindings[i]
		}
	}
	return nil
}

// InvalidPrincipalError is returned when a trust policy names a user or role
// ARN no user or role has.
type InvalidPrincipalError struct {
	ARN string
}

func (e *InvalidPrincipalError) Error() string {
	return "identity: no user or role has the ARN " + e.ARN
}

// IsBindable reports whether a trust policy's AWS principal value is one
// IAM binds to a unique ID: an IAM user's or role's ARN. Account IDs, root
// ARNs, role session ARNs and "*" are not bound.
func IsBindable(principal string) bool {
	_, _, _, user := ParseUserARN(principal)
	_, _, _, role := ParseRoleARN(principal)
	return user || role
}

// The scopes ListPolicies lists.
const (
	PolicyScopeAll   = "All"
	PolicyScopeAWS   = "AWS"
	PolicyScopeLocal = "Local"
)

// CreatePolicyInput describes a new customer managed policy, whose first
// version, v1, is its default.
type CreatePolicyInput struct {
	AccountID   string
	Name        string
	Path        string
	Description string
	Document    string
	Tags        []Tag
}

// ListPoliciesInput selects the managed policies ListPolicies returns: those
// the account can see in Scope whose path starts with PathPrefix, only those
// attached to one of its users or roles when OnlyAttached, a page of up to
// MaxItems after Marker.
type ListPoliciesInput struct {
	AccountID    string
	Scope        string
	PathPrefix   string
	Marker       string
	MaxItems     int
	OnlyAttached bool
}

// ListPolicyVersionsInput selects the versions of a managed policy.
type ListPolicyVersionsInput struct {
	AccountID string
	PolicyARN string
	Marker    string
	MaxItems  int
}

// ListAttachedPoliciesInput selects the managed policies attached to an
// entity whose path starts with PathPrefix.
type ListAttachedPoliciesInput struct {
	Entity     Entity
	PathPrefix string
	Marker     string
	MaxItems   int
}

// ListInlinePoliciesInput selects the names of an entity's inline policies.
type ListInlinePoliciesInput struct {
	Entity   Entity
	Marker   string
	MaxItems int
}

// CreateRoleInput describes a new role. MaxSessionDuration is in seconds.
// TrustPrincipals are the user and role ARNs the trust policy names, which
// the store binds to their unique IDs.
type CreateRoleInput struct {
	AccountID          string
	Name               string
	Path               string
	TrustPolicy        string
	Description        string
	Tags               []Tag
	TrustPrincipals    []string
	MaxSessionDuration int
}

// UpdateRoleInput changes a role: its description when Description is set,
// and its maximum session duration when MaxSessionDuration is not zero.
type UpdateRoleInput struct {
	Description        *string
	AccountID          string
	Name               string
	MaxSessionDuration int
}

// ListRolesInput selects the roles ListRoles returns.
type ListRolesInput struct {
	AccountID  string
	PathPrefix string
	Marker     string
	MaxItems   int
}

// OrganizationTrustPolicy is the trust policy of OrganizationRoleName, as
// Organizations creates it: the management account may assume it.
func OrganizationTrustPolicy(managementAccountID string) string {
	return `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":` +
		`{"AWS":"arn:aws:iam::` + managementAccountID + `:root"},"Action":"sts:AssumeRole"}]}`
}

// UserARN is the ARN of an IAM user, path included.
func UserARN(accountID, path, name string) string {
	return "arn:aws:iam::" + accountID + ":user" + path + name
}

// RoleARN is the ARN of a role, path included.
func RoleARN(accountID, path, name string) string {
	return "arn:aws:iam::" + accountID + ":role" + path + name
}

// PolicyARN is the ARN of a managed policy, path included.
func PolicyARN(accountID, path, name string) string {
	return "arn:aws:iam::" + accountID + ":policy" + path + name
}

// ParsePolicyARN splits the ARN of a managed policy into its account, path
// and name. ok is false for an ARN that names no managed policy.
func ParsePolicyARN(arn string) (accountID, path, name string, ok bool) {
	return parseIAMARN(arn, "policy", true)
}

// ParseUserARN splits the ARN of an IAM user into its account, path and
// name.
func ParseUserARN(arn string) (accountID, path, name string, ok bool) {
	return parseIAMARN(arn, "user", false)
}

// ParseRoleARN splits the ARN of a role into its account, path and name.
func ParseRoleARN(arn string) (accountID, path, name string, ok bool) {
	return parseIAMARN(arn, "role", false)
}

// parseIAMARN splits arn:aws:iam::<account>:<kind><path><name>, where the
// account is 12 digits, or "aws" when awsAccount, and the path is "/" or
// begins and ends with "/".
func parseIAMARN(arn, kind string, awsAccount bool) (accountID, path, name string, ok bool) {
	rest, found := strings.CutPrefix(arn, "arn:aws:iam::")
	if !found {
		return "", "", "", false
	}
	accountID, rest, found = strings.Cut(rest, ":")
	if !found || (!isAccountID(accountID) && (!awsAccount || accountID != AWSAccount)) {
		return "", "", "", false
	}
	rest, found = strings.CutPrefix(rest, kind+"/")
	if !found {
		return "", "", "", false
	}
	slash := strings.LastIndex(rest, "/")
	path, name = "/"+rest[:slash+1], rest[slash+1:]
	if name == "" {
		return "", "", "", false
	}
	return accountID, path, name, true
}

func isAccountID(s string) bool {
	if len(s) != 12 {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

// PolicySize is a policy document's size as IAM counts it against its
// quotas: its characters, white space excluded.
func PolicySize(doc string) int {
	n := utf8.RuneCountInString(doc)
	for _, c := range doc {
		switch c {
		case ' ', '\t', '\n', '\r':
			n--
		}
	}
	return n
}
