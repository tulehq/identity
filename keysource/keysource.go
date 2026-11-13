// Package keysource is a sigv4.KeySource over a running identity service: it
// asks identity's signing-key endpoint for the signing key of a request's
// credential, so a Tule service can verify requests signed with any key
// identity knows, its IAM users' and role sessions' as well as the root
// user's.
//
// The endpoint is not an AWS API. It is a signed POST of the credential's
// scope, as JSON, to Path, authenticated with SigV4 with the root user's key
// for the signing name SigningName, which every Tule service holds already.
// It answers with the derived signing key for that scope and the principal
// the key belongs to, never with a secret.
//
// The endpoint is versioned by the request. A request with no Version, as a
// v0.1.0 client sends it, is answered as v0.1.0 answered it: the principal's
// account, ARN and access key ID. A request with Version 2 is also told
// whether the principal is its account's root user and the identity
// policies in effect for it. A request with Version 3 or later is also told
// the values of the principal's condition keys: aws:PrincipalArn,
// aws:userid, aws:PrincipalType and aws:PrincipalTag. The response carries
// the Version it was answered at, so a client can tell an identity too old
// to report what it needs.
package keysource

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"tule.dev/sigv4"

	"tule.dev/identity/internal/rootcall"
)

// Path is where identity serves the signing-key endpoint. It is under
// /_internal/, which no AWS Query request uses: those are all POST /.
const Path = "/_internal/signing-key"

// The SigV4 scope a call to the endpoint is signed for.
const (
	SigningName   = rootcall.SigningName
	SigningRegion = rootcall.SigningRegion
)

// The endpoint versions.
const (
	// VersionPolicies is the first version to report the principal's Root
	// and Policies.
	VersionPolicies = 2
	// VersionAttributes is the first to report its PrincipalArn, UserId,
	// PrincipalType and Tags.
	VersionAttributes = 3
	// Version is the version this client asks for.
	Version = VersionAttributes
)

// Request is the body of a call: the scope of the credential a request was
// signed with, as sigv4.Scope holds it, and the endpoint version the caller
// speaks, 0 for v0.1.0's.
type Request struct {
	AccessKeyID  string `json:"AccessKeyId"`
	SessionToken string `json:"SessionToken,omitempty"`
	Date         string `json:"Date"`
	Region       string `json:"Region"`
	Service      string `json:"Service"`
	Version      int    `json:"Version,omitempty"`
}

// Scope is the credential scope the request carries.
func (r *Request) Scope() sigv4.Scope {
	return sigv4.Scope{
		AccessKeyID:  r.AccessKeyID,
		SessionToken: r.SessionToken,
		Date:         r.Date,
		Region:       r.Region,
		Service:      r.Service,
	}
}

// Principal is who a signing key belongs to. Root and Policies are only
// reported at VersionPolicies or later: Root for the account's root user,
// which is never evaluated against policies, and Policies for the identity
// policy documents in effect for anyone else.
//
// PrincipalARN, UserID, PrincipalType and Tags are only reported at
// VersionAttributes or later, as the values of the principal's condition
// keys; sigv4.Principal documents each. PrincipalARN is aws:PrincipalArn:
// an IAM user's or the root user's ARN, and a role session's role ARN with
// its path, empty for a session whose role is gone. UserID is aws:userid:
// an IAM user's unique ID, <role ID>:<session name> for a role session, and
// the account ID for the root user. PrincipalType is aws:PrincipalType:
// User, AssumedRole or Account. Tags are the aws:PrincipalTag values: an
// IAM user's tags, or a role session's role's, at most MaxTags of them, and
// absent when there are none.
type Principal struct {
	Tags          map[string]string `json:"Tags,omitempty"`
	AccountID     string            `json:"AccountId"`
	ARN           string            `json:"Arn"`
	PrincipalARN  string            `json:"PrincipalArn,omitempty"`
	UserID        string            `json:"UserId,omitempty"`
	AccessKeyID   string            `json:"AccessKeyId"`
	PrincipalType string            `json:"PrincipalType,omitempty"`
	Policies      []json.RawMessage `json:"Policies,omitempty"`
	Root          bool              `json:"Root,omitempty"`
}

// Response is the body of a successful call. SigningKey is the derived key
// for the scope, base64-encoded as JSON encodes bytes. Version is the
// endpoint version the call was answered at, absent for v0.1.0's.
type Response struct {
	SigningKey []byte    `json:"SigningKey"`
	Principal  Principal `json:"Principal"`
	Version    int       `json:"Version,omitempty"`
}

// ErrorResponse is the body of a failed call.
type ErrorResponse struct {
	Code    string `json:"Code"`
	Message string `json:"Message"`
}

// The codes a call fails with when identity has no key for the scope, with
// status 400. Any other failure carries another code: the endpoint's own
// authentication failures with 403, a malformed request with 400, and an
// internal failure with 500.
const (
	CodeUnknownAccessKey    = "UnknownAccessKey"
	CodeInactiveAccessKey   = "InactiveAccessKey"
	CodeInvalidSessionToken = "InvalidSessionToken"
	CodeExpiredSessionToken = "ExpiredSessionToken"
)

// ErrInactiveAccessKey is returned for an access key whose status is
// Inactive. It wraps sigv4.ErrUnknownAccessKey, so a verifier refuses it as
// AWS refuses an inactive key, as an invalid one, while the service can still
// tell the two apart.
var ErrInactiveAccessKey = fmt.Errorf("keysource: inactive access key: %w",
	sigv4.ErrUnknownAccessKey)

// Error is a failed call that is not one of the key refusals: the endpoint
// refused the caller, or failed. A verifier reports it as
// sigv4.KindKeyLookupFailed.
type Error struct {
	Code    string
	Message string
	Status  int
}

func (e *Error) Error() string {
	return fmt.Sprintf("keysource: signing-key endpoint answered %d %s: %s",
		e.Status, e.Code, e.Message)
}

// Config configures a Client.
type Config struct {
	// HTTPClient makes the calls. It defaults to http.DefaultClient.
	HTTPClient *http.Client
	// Endpoint is identity's base URL, such as http://localhost:9030.
	Endpoint string
	// AccessKeyID and SecretAccessKey are the root user's key, which the
	// calls are signed with.
	AccessKeyID     string
	SecretAccessKey string
}

// Client is a sigv4.KeySource that asks identity for every key. It holds no
// cache, so a key identity deactivates or deletes is refused on the next
// request. It is safe for concurrent use.
type Client struct {
	caller *rootcall.Caller
}

var _ sigv4.KeySource = (*Client)(nil)

// New returns a Client for cfg. It fails when the endpoint is not an
// absolute http or https URL, or the key is not set.
func New(cfg Config) (*Client, error) {
	c, err := rootcall.New(cfg.Endpoint, cfg.AccessKeyID, cfg.SecretAccessKey, cfg.HTTPClient)
	if err != nil {
		return nil, fmt.Errorf("keysource: %w", err)
	}
	return &Client{caller: c}, nil
}

// SigningKey asks identity for the signing key of scope, with the
// principal's Root, Policies and condition key values. It returns sigv4.ErrUnknownAccessKey,
// ErrInactiveAccessKey (which wraps it), sigv4.ErrInvalidSessionToken or
// sigv4.ErrExpiredSessionToken when identity has no key for the scope, and
// an *Error or a transport error otherwise, an identity that answers below
// Version included: it cannot say what the principal may do.
func (c *Client) SigningKey(ctx context.Context, scope sigv4.Scope) (sigv4.Key, error) {
	//nolint:gosec // G117: the scope's session token is what identity checks
	body, err := json.Marshal(Request{
		AccessKeyID:  scope.AccessKeyID,
		SessionToken: scope.SessionToken,
		Date:         scope.Date,
		Region:       scope.Region,
		Service:      scope.Service,
		Version:      Version,
	})
	if err != nil {
		return sigv4.Key{}, fmt.Errorf("keysource: encode the request: %w", err)
	}
	status, raw, err := c.caller.Post(ctx, Path, body, MaxResponseSize)
	if err != nil {
		return sigv4.Key{}, fmt.Errorf("keysource: %w", err)
	}

	if status != http.StatusOK {
		return sigv4.Key{}, decodeError(status, raw)
	}
	var out Response
	if err = json.Unmarshal(raw, &out); err != nil {
		return sigv4.Key{}, fmt.Errorf("keysource: decode the response: %w", err)
	}
	if out.Version < Version {
		return sigv4.Key{}, &Error{
			Status: status, Code: CodeVersionUnsupported,
			Message: fmt.Sprintf("the endpoint answered at version %d, which reports no "+
				"principal attributes; this client needs version %d or later",
				out.Version, Version),
		}
	}
	return sigv4.Key{
		Principal: sigv4.Principal{
			Tags:         out.Principal.Tags,
			AccountID:    out.Principal.AccountID,
			ARN:          out.Principal.ARN,
			PrincipalARN: out.Principal.PrincipalARN,
			UserID:       out.Principal.UserID,
			AccessKeyID:  out.Principal.AccessKeyID,
			Type:         sigv4.PrincipalType(out.Principal.PrincipalType),
			Policies:     out.Principal.Policies,
			Root:         out.Principal.Root,
		},
		Signing: out.SigningKey,
	}, nil
}

// CodeVersionUnsupported is the Code of the *Error SigningKey returns for an
// identity that answers below Version.
const CodeVersionUnsupported = "VersionUnsupported"

// The bounds of a principal's policies on the wire, from the IAM quotas
// (the IAM User Guide, IAM and STS quotas) and the IAM model. Each document
// is at most maxDocumentChars characters, white space included
// (policyDocumentType); white space is not counted against the size quotas
// below, and inside a string it is kept. An entity may have any number of
// inline policies within its aggregate size ("You can add as many inline
// policies as you want"), and the smallest identity policy has
// minPolicyChars characters without white space, so a role has at most
// 10,240/59 of them. The endpoint writes documents as JSON with <, > and &
// escaped, six bytes each, so a counted character takes at most
// escapedBytes.
const (
	maxDocumentChars = 131072
	minPolicyChars   = 59 // {"Statement":{"Effect":"Deny","Action":"*","Resource":"*"}}
	escapedBytes     = 6

	roleInlineChars  = 10240
	roleManaged      = 20
	managedChars     = 6144
	userInlineChars  = 2048
	userManaged      = 10
	responseOverhead = 64 << 10

	// roleInlineBytes is the most a role's inline policies take: as many as
	// fit, each of maxDocumentChars, with every counted character escaped.
	roleInlineBytes = roleInlineChars/minPolicyChars*maxDocumentChars +
		(escapedBytes-1)*roleInlineChars
	// roleManagedBytes is the most its attached managed policies take.
	roleManagedBytes = roleManaged * (maxDocumentChars + (escapedBytes-1)*managedChars)
	// userPolicyBytes is a user's equivalent, which is less.
	userPolicyBytes = userInlineChars/minPolicyChars*maxDocumentChars +
		(escapedBytes-1)*userInlineChars +
		userManaged*(maxDocumentChars+(escapedBytes-1)*managedChars)

	// maxPolicyBytes, about 24.8 MiB, is a role's, and so a session's.
	maxPolicyBytes = roleInlineBytes + roleManagedBytes
)

// MaxTags is the most tags a principal is reported with: IAM's limit of 50
// tags on a user or role (tagListType), which a role session takes from its
// role, since it carries no session tags of its own.
const MaxTags = 50

// The bound of a principal's tags on the wire. A tag key is at most
// maxTagKeyChars characters and a value maxTagValueChars (tagKeyType and
// tagValueType); the endpoint writes each character in at most
// escapedBytes, a \u escape, which covers U+2028 and U+2029 (\p{Z}, which
// tags allow) and any character's UTF-8. A tag also takes its two quoted
// strings' quotes, a colon and a comma, tagPunctuation. The session tags
// AWS allows besides a role's tags (at most 50, in id_session-tags) would
// at most double maxTagBytes, and that still fits the margin below.
const (
	maxTagKeyChars   = 128
	maxTagValueChars = 256
	tagPunctuation   = 6
	maxTagBytes      = MaxTags *
		((maxTagKeyChars+maxTagValueChars)*escapedBytes + tagPunctuation)
)

// MaxResponseSize bounds what the client reads of a response: a signing
// key and a principal with its policies and tags, at most maxPolicyBytes
// and maxTagBytes and a little, with a quarter more as margin, rounded to
// 32 MiB. A larger response is refused with an error that says so.
const MaxResponseSize = 32 << 20

// The bound covers the largest set of policies and tags identity can hold.
var _ = [MaxResponseSize - (maxPolicyBytes + maxPolicyBytes/4 + maxTagBytes +
	responseOverhead)]struct{}{}

// It would cover twice the tags too, were sessions to carry session tags.
var _ = [MaxResponseSize - (maxPolicyBytes + maxPolicyBytes/4 + 2*maxTagBytes +
	responseOverhead)]struct{}{}

// A user's policies fit within a role's.
var _ = [maxPolicyBytes - userPolicyBytes]struct{}{}

func decodeError(status int, raw []byte) error {
	var e ErrorResponse
	if err := json.Unmarshal(raw, &e); err != nil {
		return &Error{Status: status, Message: string(raw)}
	}
	if status == http.StatusBadRequest {
		switch e.Code {
		case CodeUnknownAccessKey:
			return sigv4.ErrUnknownAccessKey
		case CodeInactiveAccessKey:
			return ErrInactiveAccessKey
		case CodeInvalidSessionToken:
			return sigv4.ErrInvalidSessionToken
		case CodeExpiredSessionToken:
			return sigv4.ErrExpiredSessionToken
		}
	}
	return &Error{Status: status, Code: e.Code, Message: e.Message}
}
