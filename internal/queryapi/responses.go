package queryapi

import (
	"fmt"
	"strings"
	"time"
)

// The result documents this service writes, following the SDK's response
// snapshots and the API references' examples. A field the model marks
// optional is left out when this service has no value for it; the lists a
// list operation returns are always present, empty or not.

// List is a list on the wire: its items as <member> elements of its own
// element, which is written even when it holds none.
type List[T any] struct {
	Members []T `xml:"member"`
}

// ListOf returns items as a List.
func ListOf[T any](items []T) List[T] {
	return List[T]{Members: items}
}

// Tag is a tag on a user.
type Tag struct {
	Key   string `xml:"Key"`
	Value string `xml:"Value"`
}

// Timestamp is a time on the wire: ISO 8601 in UTC to the second, as the
// API references' examples show (2013-10-02T17:01:44Z).
type Timestamp string

// Stamp returns t as a wire timestamp.
func Stamp(t time.Time) Timestamp {
	return Timestamp(t.UTC().Format(time.RFC3339))
}

// User is an IAM user, or the root user, which has no path or name. Tags are
// only reported by GetUser, and only when the IAM user has some.
type User struct {
	Tags       *List[Tag] `xml:"Tags,omitempty"`
	Path       string     `xml:"Path,omitempty"`
	UserName   string     `xml:"UserName,omitempty"`
	UserID     string     `xml:"UserId"`
	Arn        string     `xml:"Arn"`
	CreateDate Timestamp  `xml:"CreateDate"`
}

// UserResult is the result of CreateUser and GetUser.
type UserResult struct {
	User User `xml:"User"`
}

// ListUsersResult is the result of ListUsers.
type ListUsersResult struct {
	Marker      string     `xml:"Marker,omitempty"`
	Users       List[User] `xml:"Users"`
	IsTruncated bool       `xml:"IsTruncated"`
}

// AccessKey is a new access key, with its secret, which only CreateAccessKey
// returns.
type AccessKey struct {
	UserName        string    `xml:"UserName"`
	AccessKeyID     string    `xml:"AccessKeyId"`
	Status          string    `xml:"Status"`
	SecretAccessKey string    `xml:"SecretAccessKey"`
	CreateDate      Timestamp `xml:"CreateDate"`
}

// CreateAccessKeyResult is the result of CreateAccessKey.
type CreateAccessKeyResult struct {
	AccessKey AccessKey `xml:"AccessKey"`
}

// AccessKeyMetadata is an access key as ListAccessKeys reports it. The root
// user's has no UserName.
type AccessKeyMetadata struct {
	UserName    string    `xml:"UserName,omitempty"`
	AccessKeyID string    `xml:"AccessKeyId"`
	Status      string    `xml:"Status"`
	CreateDate  Timestamp `xml:"CreateDate"`
}

// ListAccessKeysResult is the result of ListAccessKeys.
type ListAccessKeysResult struct {
	Marker            string                  `xml:"Marker,omitempty"`
	AccessKeyMetadata List[AccessKeyMetadata] `xml:"AccessKeyMetadata"`
	IsTruncated       bool                    `xml:"IsTruncated"`
}

// ListUserTagsResult is the result of ListUserTags.
type ListUserTagsResult struct {
	Marker      string    `xml:"Marker,omitempty"`
	Tags        List[Tag] `xml:"Tags"`
	IsTruncated bool      `xml:"IsTruncated"`
}

// AccessKeyLastUsed is when, where and with what an access key was last
// used. ServiceName and Region are required by the model, and "N/A" for a
// key never used, which has no LastUsedDate.
type AccessKeyLastUsed struct {
	LastUsedDate Timestamp `xml:"LastUsedDate,omitempty"`
	ServiceName  string    `xml:"ServiceName"`
	Region       string    `xml:"Region"`
}

// GetAccessKeyLastUsedResult is the result of GetAccessKeyLastUsed. The root
// user's key has no UserName.
type GetAccessKeyLastUsedResult struct {
	UserName          string            `xml:"UserName,omitempty"`
	AccessKeyLastUsed AccessKeyLastUsed `xml:"AccessKeyLastUsed"`
}

// GetCallerIdentityResult is the result of GetCallerIdentity.
type GetCallerIdentityResult struct {
	UserID  string `xml:"UserId"`
	Account string `xml:"Account"`
	Arn     string `xml:"Arn"`
}

// GetAccessKeyInfoResult is the result of GetAccessKeyInfo.
type GetAccessKeyInfoResult struct {
	Account string `xml:"Account"`
}

// Credentials are temporary security credentials.
type Credentials struct {
	AccessKeyID     string    `xml:"AccessKeyId"`
	SecretAccessKey string    `xml:"SecretAccessKey"`
	SessionToken    string    `xml:"SessionToken"`
	Expiration      Timestamp `xml:"Expiration"`
}

// AssumedRoleUser identifies a role session.
type AssumedRoleUser struct {
	AssumedRoleID string `xml:"AssumedRoleId"`
	Arn           string `xml:"Arn"`
}

// AssumeRoleResult is the result of AssumeRole.
type AssumeRoleResult struct {
	Credentials     Credentials     `xml:"Credentials"`
	AssumedRoleUser AssumedRoleUser `xml:"AssumedRoleUser"`
}

// Policy is a managed policy. Description and Tags are only reported by
// CreatePolicy and GetPolicy, as the listings return a subset of a policy's
// attributes (the ListPolicies reference).
type Policy struct {
	Tags                          *List[Tag] `xml:"Tags,omitempty"`
	PolicyName                    string     `xml:"PolicyName"`
	PolicyID                      string     `xml:"PolicyId"`
	Arn                           string     `xml:"Arn"`
	Path                          string     `xml:"Path"`
	DefaultVersionID              string     `xml:"DefaultVersionId"`
	Description                   string     `xml:"Description,omitempty"`
	CreateDate                    Timestamp  `xml:"CreateDate"`
	UpdateDate                    Timestamp  `xml:"UpdateDate"`
	AttachmentCount               int        `xml:"AttachmentCount"`
	PermissionsBoundaryUsageCount int        `xml:"PermissionsBoundaryUsageCount"`
	IsAttachable                  bool       `xml:"IsAttachable"`
}

// PolicyResult is the result of CreatePolicy and GetPolicy.
type PolicyResult struct {
	Policy Policy `xml:"Policy"`
}

// ListPoliciesResult is the result of ListPolicies.
type ListPoliciesResult struct {
	Marker      string       `xml:"Marker,omitempty"`
	Policies    List[Policy] `xml:"Policies"`
	IsTruncated bool         `xml:"IsTruncated"`
}

// PolicyVersion is a version of a managed policy. Document, URL-encoded as
// IAM returns policy documents, is only reported by GetPolicyVersion.
type PolicyVersion struct {
	Document         string    `xml:"Document,omitempty"`
	VersionID        string    `xml:"VersionId"`
	CreateDate       Timestamp `xml:"CreateDate"`
	IsDefaultVersion bool      `xml:"IsDefaultVersion"`
}

// PolicyVersionResult is the result of CreatePolicyVersion and
// GetPolicyVersion.
type PolicyVersionResult struct {
	PolicyVersion PolicyVersion `xml:"PolicyVersion"`
}

// ListPolicyVersionsResult is the result of ListPolicyVersions.
type ListPolicyVersionsResult struct {
	Marker      string              `xml:"Marker,omitempty"`
	Versions    List[PolicyVersion] `xml:"Versions"`
	IsTruncated bool                `xml:"IsTruncated"`
}

// AttachedPolicy is a managed policy attached to a user or role.
type AttachedPolicy struct {
	PolicyName string `xml:"PolicyName"`
	PolicyArn  string `xml:"PolicyArn"`
}

// ListAttachedPoliciesResult is the result of ListAttachedUserPolicies and
// ListAttachedRolePolicies.
type ListAttachedPoliciesResult struct {
	Marker           string               `xml:"Marker,omitempty"`
	AttachedPolicies List[AttachedPolicy] `xml:"AttachedPolicies"`
	IsTruncated      bool                 `xml:"IsTruncated"`
}

// ListInlinePoliciesResult is the result of ListUserPolicies and
// ListRolePolicies.
type ListInlinePoliciesResult struct {
	Marker      string       `xml:"Marker,omitempty"`
	PolicyNames List[string] `xml:"PolicyNames"`
	IsTruncated bool         `xml:"IsTruncated"`
}

// GetUserPolicyResult is the result of GetUserPolicy. PolicyDocument is
// URL-encoded.
type GetUserPolicyResult struct {
	UserName       string `xml:"UserName"`
	PolicyName     string `xml:"PolicyName"`
	PolicyDocument string `xml:"PolicyDocument"`
}

// GetRolePolicyResult is the result of GetRolePolicy. PolicyDocument is
// URL-encoded.
type GetRolePolicyResult struct {
	RoleName       string `xml:"RoleName"`
	PolicyName     string `xml:"PolicyName"`
	PolicyDocument string `xml:"PolicyDocument"`
}

// Role is an IAM role. AssumeRolePolicyDocument is URL-encoded. Tags are
// only reported by CreateRole and GetRole, and only when the role has some.
type Role struct {
	Tags                     *List[Tag] `xml:"Tags,omitempty"`
	Path                     string     `xml:"Path"`
	RoleName                 string     `xml:"RoleName"`
	RoleID                   string     `xml:"RoleId"`
	Arn                      string     `xml:"Arn"`
	CreateDate               Timestamp  `xml:"CreateDate"`
	AssumeRolePolicyDocument string     `xml:"AssumeRolePolicyDocument"`
	Description              string     `xml:"Description,omitempty"`
	MaxSessionDuration       int        `xml:"MaxSessionDuration"`
}

// RoleResult is the result of CreateRole and GetRole.
type RoleResult struct {
	Role Role `xml:"Role"`
}

// ListRolesResult is the result of ListRoles.
type ListRolesResult struct {
	Marker      string     `xml:"Marker,omitempty"`
	Roles       List[Role] `xml:"Roles"`
	IsTruncated bool       `xml:"IsTruncated"`
}

// EmptyResult is the result of an operation whose output shape has no
// members, such as UpdateRole: an empty Result element.
type EmptyResult struct{}

// EncodeDocument URL-encodes a policy document as IAM returns one,
// compliant with RFC 3986: every byte but the unreserved characters is
// percent-encoded.
func EncodeDocument(doc string) string {
	var b strings.Builder
	for i := range len(doc) {
		c := doc[i]
		switch {
		case 'A' <= c && c <= 'Z', 'a' <= c && c <= 'z', '0' <= c && c <= '9',
			c == '-', c == '.', c == '_', c == '~':
			b.WriteByte(c)
		default:
			fmt.Fprintf(&b, "%%%02X", c)
		}
	}
	return b.String()
}
