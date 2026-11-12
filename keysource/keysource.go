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
package keysource

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"tule.dev/sigv4"
)

// Path is where identity serves the signing-key endpoint. It is under
// /_internal/, which no AWS Query request uses: those are all POST /.
const Path = "/_internal/signing-key"

// The SigV4 scope a call to the endpoint is signed for.
const (
	SigningName   = "identity"
	SigningRegion = "us-east-1"
)

// Request is the body of a call: the scope of the credential a request was
// signed with, as sigv4.Scope holds it.
type Request struct {
	AccessKeyID  string `json:"AccessKeyId"`
	SessionToken string `json:"SessionToken,omitempty"`
	Date         string `json:"Date"`
	Region       string `json:"Region"`
	Service      string `json:"Service"`
}

// Principal is who a signing key belongs to.
type Principal struct {
	AccountID   string `json:"AccountId"`
	ARN         string `json:"Arn"`
	AccessKeyID string `json:"AccessKeyId"`
}

// Response is the body of a successful call. SigningKey is the derived key
// for the scope, base64-encoded as JSON encodes bytes.
type Response struct {
	Principal  Principal `json:"Principal"`
	SigningKey []byte    `json:"SigningKey"`
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
	http   *http.Client
	signer *v4.Signer
	creds  aws.Credentials
	url    string
}

var _ sigv4.KeySource = (*Client)(nil)

// New returns a Client for cfg. It fails when the endpoint is not an
// absolute http or https URL, or the key is not set.
func New(cfg Config) (*Client, error) {
	u, err := url.Parse(cfg.Endpoint)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil, fmt.Errorf("keysource: the endpoint %q is not an http or https URL",
			cfg.Endpoint)
	}
	if cfg.AccessKeyID == "" || cfg.SecretAccessKey == "" {
		return nil, errors.New("keysource: the root user's access key ID and secret are required")
	}
	hc := cfg.HTTPClient
	if hc == nil {
		hc = http.DefaultClient
	}
	return &Client{
		http:   hc,
		signer: v4.NewSigner(),
		creds: aws.Credentials{
			AccessKeyID:     cfg.AccessKeyID,
			SecretAccessKey: cfg.SecretAccessKey,
		},
		url: strings.TrimSuffix(u.String(), "/") + Path,
	}, nil
}

// SigningKey asks identity for the signing key of scope. It returns
// sigv4.ErrUnknownAccessKey, ErrInactiveAccessKey (which wraps it),
// sigv4.ErrInvalidSessionToken or sigv4.ErrExpiredSessionToken when identity
// has no key for the scope, and an *Error or a transport error otherwise.
func (c *Client) SigningKey(ctx context.Context, scope sigv4.Scope) (sigv4.Key, error) {
	//nolint:gosec // G117: the scope's session token is what identity checks
	body, err := json.Marshal(Request(scope))
	if err != nil {
		return sigv4.Key{}, fmt.Errorf("keysource: encode the request: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.url, bytes.NewReader(body))
	if err != nil {
		return sigv4.Key{}, fmt.Errorf("keysource: build the request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	sum := sha256.Sum256(body)
	if err = c.signer.SignHTTP(ctx, c.creds, req, hex.EncodeToString(sum[:]),
		SigningName, SigningRegion, time.Now()); err != nil {
		return sigv4.Key{}, fmt.Errorf("keysource: sign the request: %w", err)
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return sigv4.Key{}, fmt.Errorf("keysource: call the signing-key endpoint: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseSize))
	if err != nil {
		return sigv4.Key{}, fmt.Errorf("keysource: read the response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return sigv4.Key{}, decodeError(resp.StatusCode, raw)
	}
	var out Response
	if err = json.Unmarshal(raw, &out); err != nil {
		return sigv4.Key{}, fmt.Errorf("keysource: decode the response: %w", err)
	}
	return sigv4.Key{
		Principal: sigv4.Principal(out.Principal),
		Signing:   out.SigningKey,
	}, nil
}

// maxResponseSize bounds what is read of a response: a signing key, a
// principal and their JSON need well under a kilobyte.
const maxResponseSize = 64 << 10

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
