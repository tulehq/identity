package queryapi

import "time"

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
