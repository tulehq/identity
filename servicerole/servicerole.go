// Package servicerole is the client of identity's assume-role endpoint,
// through which a Tule service assumes a role as an AWS service principal,
// as Lambda assumes a function's execution role: for a role whose trust
// policy names the service, such as {"Service": "lambda.amazonaws.com"}.
//
// The endpoint is not an AWS API. Like the signing-key endpoint, it is a
// SigV4-signed POST, with the root user's key for the signing name
// identity, of a JSON request to Path. It evaluates the role's trust policy
// for the service principal, and no identity policies, since a service
// principal has none, and answers with a session of the role. The session
// carries the role's policies, as an AssumeRole session does.
package servicerole

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"time"

	"tule.dev/identity/internal/rootcall"
)

// Path is where identity serves the assume-role endpoint, beside the
// signing-key endpoint under /_internal/.
const Path = "/_internal/assume-role"

// Request is the body of a call. DurationSeconds is 900 to 43200, and no
// more than the role's MaxSessionDuration; 0 asks for the default, an hour.
// SourceArn and SourceAccount, when set, name the resource the service acts
// for and its account, such as a function and its account, and are supplied
// to the trust policy as aws:SourceArn and aws:SourceAccount, as AWS
// services supply them against the confused deputy problem (the IAM User
// Guide, the confused deputy problem).
type Request struct {
	RoleArn          string `json:"RoleArn"`
	RoleSessionName  string `json:"RoleSessionName"`
	ServicePrincipal string `json:"ServicePrincipal"`
	SourceArn        string `json:"SourceArn,omitempty"`
	SourceAccount    string `json:"SourceAccount,omitempty"`
	DurationSeconds  int    `json:"DurationSeconds,omitempty"`
}

// Credentials are a role session's temporary credentials.
type Credentials struct {
	Expiration      time.Time `json:"Expiration"`
	AccessKeyID     string    `json:"AccessKeyId"`
	SecretAccessKey string    `json:"SecretAccessKey"`
	SessionToken    string    `json:"SessionToken"`
}

// AssumedRoleUser identifies a role session, as AssumeRole reports it.
type AssumedRoleUser struct {
	AssumedRoleID string `json:"AssumedRoleId"`
	Arn           string `json:"Arn"`
}

// Session is the body of a successful call.
type Session struct {
	Credentials     Credentials     `json:"Credentials"`
	AssumedRoleUser AssumedRoleUser `json:"AssumedRoleUser"`
}

// ErrorResponse is the body of a failed call.
type ErrorResponse struct {
	Code    string `json:"Code"`
	Message string `json:"Message"`
}

// The codes a call fails with. The endpoint's own authentication failures
// are 403 with the sigv4 Kind as the code, and a failure of identity is 500
// InternalFailure.
const (
	// CodeNoSuchRole, 404: no role has the ARN, compared with its case.
	CodeNoSuchRole = "NoSuchRole"
	// CodeNotTrusted, 403: the role's trust policy does not allow the
	// service principal sts:AssumeRole.
	CodeNotTrusted = "NotTrusted"
	// CodeInvalidDuration, 400: DurationSeconds is out of 900 to 43200, or
	// over the role's MaxSessionDuration.
	CodeInvalidDuration = "InvalidDuration"
	// CodeInvalidRequest, 400: the body is not a request, or a field is
	// malformed.
	CodeInvalidRequest = "InvalidRequest"
)

// The errors the client returns for the refusals a caller can act on.
var (
	ErrNoSuchRole      = errors.New("servicerole: no such role")
	ErrNotTrusted      = errors.New("servicerole: the role does not trust the service")
	ErrInvalidDuration = errors.New("servicerole: invalid session duration")
)

// Error is any other failed call.
type Error struct {
	Code    string
	Message string
	Status  int
}

func (e *Error) Error() string {
	return fmt.Sprintf("servicerole: the assume-role endpoint answered %d %s: %s",
		e.Status, e.Code, e.Message)
}

// servicePrincipal is the form of an AWS service principal: dot-separated
// DNS labels ending in amazonaws.com, such as lambda.amazonaws.com
// ("AWS JSON policy elements: Principal", AWS service principals).
var servicePrincipal = regexp.MustCompile(
	`^(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+amazonaws\.com$`)

// maxServicePrincipal bounds a service principal's length, that of a DNS
// name.
const maxServicePrincipal = 253

// IsServicePrincipal reports whether s has the form of a service principal.
func IsServicePrincipal(s string) bool {
	return len(s) <= maxServicePrincipal && servicePrincipal.MatchString(s)
}

// sourceARN is the form of an AWS ARN, arn:aws:service:region:account:
// resource, where region and account may be empty, as in an S3 bucket's,
// and an account is 12 digits (the IAM User Guide, IAM identifiers, ARNs).
var sourceARN = regexp.MustCompile(`^arn:aws:[a-z0-9-]+:[a-z0-9-]*:(?:\d{12})?:.+$`)

// The length bounds of an ARN, as IAM's arnType has them.
const (
	minARN = 20
	maxARN = 2048
)

// IsSourceArn reports whether s has the form of an ARN.
func IsSourceArn(s string) bool {
	return len(s) >= minARN && len(s) <= maxARN && sourceARN.MatchString(s)
}

var accountID = regexp.MustCompile(`^\d{12}$`)

// IsAccountID reports whether s is an AWS account ID, 12 digits.
func IsAccountID(s string) bool {
	return accountID.MatchString(s)
}

// Option sets an optional field of an AssumeServiceRole request.
type Option func(*Request)

// WithSourceArn supplies arn, the resource the service acts for, as
// aws:SourceArn.
func WithSourceArn(arn string) Option {
	return func(r *Request) { r.SourceArn = arn }
}

// WithSourceAccount supplies account, the account of the resource the
// service acts for, as aws:SourceAccount.
func WithSourceAccount(account string) Option {
	return func(r *Request) { r.SourceAccount = account }
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

// Client calls the assume-role endpoint. It is safe for concurrent use.
type Client struct {
	caller *rootcall.Caller
}

// New returns a Client for cfg. It fails when the endpoint is not an
// absolute http or https URL, or the key is not set.
func New(cfg Config) (*Client, error) {
	c, err := rootcall.New(cfg.Endpoint, cfg.AccessKeyID, cfg.SecretAccessKey, cfg.HTTPClient)
	if err != nil {
		return nil, fmt.Errorf("servicerole: %w", err)
	}
	return &Client{caller: c}, nil
}

// maxResponseSize bounds what is read of a response: credentials and an
// assumed-role user need well under a kilobyte.
const maxResponseSize = 64 << 10

// AssumeServiceRole assumes the role roleARN names as servicePrincipal, for
// a session named sessionName that lasts duration, a whole number of
// seconds, or an hour when duration is 0, with the options set. It returns
// ErrNoSuchRole,
// ErrNotTrusted or ErrInvalidDuration for those refusals, and an *Error or
// a transport error otherwise.
func (c *Client) AssumeServiceRole(
	ctx context.Context,
	roleARN, sessionName, servicePrincipal string,
	duration time.Duration,
	opts ...Option,
) (*Session, error) {
	if duration%time.Second != 0 {
		return nil, fmt.Errorf(
			"%w: %s is not a whole number of seconds",
			ErrInvalidDuration,
			duration,
		)
	}
	req := Request{
		RoleArn:          roleARN,
		RoleSessionName:  sessionName,
		ServicePrincipal: servicePrincipal,
		DurationSeconds:  int(duration / time.Second),
	}
	for _, o := range opts {
		o(&req)
	}
	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("servicerole: encode the request: %w", err)
	}
	status, raw, err := c.caller.Post(ctx, Path, body, maxResponseSize)
	if err != nil {
		return nil, fmt.Errorf("servicerole: %w", err)
	}
	if status != http.StatusOK {
		return nil, decodeError(status, raw)
	}
	var out Session
	if err = json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("servicerole: decode the response: %w", err)
	}
	return &out, nil
}

func decodeError(status int, raw []byte) error {
	var e ErrorResponse
	if err := json.Unmarshal(raw, &e); err != nil {
		return &Error{Status: status, Message: string(raw)}
	}
	switch {
	case status == http.StatusNotFound && e.Code == CodeNoSuchRole:
		return fmt.Errorf("%w: %s", ErrNoSuchRole, e.Message)
	case status == http.StatusForbidden && e.Code == CodeNotTrusted:
		return fmt.Errorf("%w: %s", ErrNotTrusted, e.Message)
	case status == http.StatusBadRequest && e.Code == CodeInvalidDuration:
		return fmt.Errorf("%w: %s", ErrInvalidDuration, e.Message)
	}
	return &Error{Status: status, Code: e.Code, Message: e.Message}
}
