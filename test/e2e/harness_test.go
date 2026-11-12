//go:build e2e

package e2e

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/aws/smithy-go"
	"github.com/gasmod/gas"
	"github.com/gasmod/gas/config"

	"tule.dev/identity/internal/app"
)

// server is the app under test, served by the app's own *http.Server over a
// real TCP listener, as in accounts' harness: the listener is created here
// because gas.App.Serve exposes neither the listener nor its port, and
// everything else is the server gas built from the bound configuration,
// reached over the network and shut down through gas.App.Stop.
type server struct {
	app      *gas.App
	listener net.Listener
	client   *http.Client
	served   chan error
	URL      string
	Addr     string
	stopped  bool
}

// clientTimeout bounds a test's own requests, so a hung server fails the test
// instead of the suite's timeout.
const clientTimeout = 30 * time.Second

// The management account's root user. It is the AWS documentation's example
// key: GetAccessKeyInfo takes an access key ID of at least 16 characters
// (accessKeyIdType), so a short ID such as "test" could not be looked up.
const (
	rootKeyID  = "AKIAIOSFODNN7EXAMPLE"
	rootSecret = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
)

// defaultAccountID is the account the root key belongs to when
// TULE_Identity_AccountID is unset.
const defaultAccountID = "000000000000"

// signingRegion is the region IAM signs with (the spec: global, us-east-1).
const signingRegion = "us-east-1"

// ID formats. The prefixes are those of the IAM User Guide's "Unique
// identifiers" table (IAM identifiers): AIDA for an IAM user, AKIA for a
// long-term access key, ASIA for a temporary one, AROA for a role. An access
// key ID is 20 characters, as every example in the IAM and STS references is
// (AKIAIOSFODNN7EXAMPLE).
var (
	userIDPattern    = regexp.MustCompile(`^AIDA[A-Z0-9]+$`)
	accessKeyPattern = regexp.MustCompile(`^AKIA[A-Z0-9]{16}$`)
	tempKeyPattern   = regexp.MustCompile(`^ASIA[A-Z0-9]{16}$`)
	roleIDPattern    = regexp.MustCompile(`^AROA[A-Z0-9]+$`)
)

// rootCreds are the root user's credentials.
func rootCreds() aws.Credentials {
	return aws.Credentials{AccessKeyID: rootKeyID, SecretAccessKey: rootSecret}
}

// startServer starts the app on a fresh store, with env setting extra TULE_
// variables.
func startServer(t *testing.T, env map[string]string) *server {
	t.Helper()

	setEnv(t, env)

	cfg, err := app.LoadConfigFrom(config.NewEnvProvider(
		config.WithEnvSeparator("_"),
		config.WithEnvPrefix("TULE_"),
	))
	if err != nil {
		t.Fatalf("load config: %v", err)
	}

	a, err := app.New(cfg)
	if err != nil {
		t.Fatalf("new app: %v", err)
	}

	// Start binds the configuration and initializes the services, so the
	// server built after it carries the configured timeouts.
	if err = a.Start(context.Background()); err != nil {
		t.Fatalf("start app: %v", err)
	}

	srv := serve(t, a)
	t.Cleanup(func() { srv.Stop(t) })
	return srv
}

func setEnv(t *testing.T, env map[string]string) {
	t.Helper()

	t.Setenv("TULE_GasEnv", "testing")
	t.Setenv("TULE_Store_Path", filepath.Join(t.TempDir(), "identity.db"))
	t.Setenv("TULE_Auth_AccessKeyID", rootKeyID)
	t.Setenv("TULE_Auth_SecretAccessKey", rootSecret)
	for k, v := range env {
		t.Setenv(k, v)
	}
}

// serve puts the app's own server on a loopback listener on a free port.
func serve(t *testing.T, a *gas.App) *server {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	srv := &server{
		app:      a,
		listener: listener,
		client:   &http.Client{Timeout: clientTimeout},
		served:   make(chan error, 1),
		Addr:     listener.Addr().String(),
		URL:      "http://" + listener.Addr().String(),
	}

	go func() {
		srv.served <- a.Server().Serve(listener)
	}()

	return srv
}

// Client returns an HTTP client for the server.
func (s *server) Client() *http.Client {
	return s.client
}

// Stop shuts the app down the way a signal does, through gas.App.Stop, and
// fails the test if the shutdown or the server itself reported an error. It
// is idempotent, so a test can stop the server early and let the cleanup run
// anyway.
func (s *server) Stop(t *testing.T) {
	t.Helper()

	if s.stopped {
		return
	}
	s.stopped = true

	// Close the client's spare connections first; the server would otherwise
	// wait for them to age out during the shutdown.
	s.client.CloseIdleConnections()

	if err := s.app.Stop(context.Background()); err != nil {
		t.Errorf("stop app: %v", err)
	}

	select {
	case err := <-s.served:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			t.Errorf("serve: %v", err)
		}
	case <-time.After(clientTimeout):
		t.Error("serve did not return after shutdown")
	}
}

// iamFor returns an IAM client for srv signing with creds. Retries are off,
// so a refused request fails at once with the error the service sent.
func iamFor(srv *server, creds aws.Credentials) *iam.Client {
	return iam.New(iam.Options{
		Region:           signingRegion,
		BaseEndpoint:     aws.String(srv.URL),
		Credentials:      credentials.StaticCredentialsProvider{Value: creds},
		HTTPClient:       srv.Client(),
		RetryMaxAttempts: 1,
	})
}

// stsFor returns an STS client for srv signing with creds, at the same base
// URL as the IAM client.
func stsFor(srv *server, creds aws.Credentials) *sts.Client {
	return sts.New(sts.Options{
		Region:           signingRegion,
		BaseEndpoint:     aws.String(srv.URL),
		Credentials:      credentials.StaticCredentialsProvider{Value: creds},
		HTTPClient:       srv.Client(),
		RetryMaxAttempts: 1,
	})
}

// rootIAM starts a server on a fresh store and returns it with an IAM client
// signing as the root user.
func rootIAM(t *testing.T) (*server, *iam.Client) {
	t.Helper()
	srv := startServer(t, nil)
	return srv, iamFor(srv, rootCreds())
}

// createUser creates a user at the default path and returns its name.
func createUser(t *testing.T, c *iam.Client, name string) string {
	t.Helper()
	_, err := c.CreateUser(t.Context(), &iam.CreateUserInput{UserName: aws.String(name)})
	requireNoErr(t, err, "create user "+name)
	return name
}

// createKey creates an access key for user and returns it as credentials.
func createKey(t *testing.T, c *iam.Client, user string) aws.Credentials {
	t.Helper()
	out, err := c.CreateAccessKey(t.Context(), &iam.CreateAccessKeyInput{
		UserName: aws.String(user),
	})
	requireNoErr(t, err, "create access key for "+user)
	if out.AccessKey == nil {
		t.Fatalf("create access key for %s returned no key", user)
	}
	return aws.Credentials{
		AccessKeyID:     aws.ToString(out.AccessKey.AccessKeyId),
		SecretAccessKey: aws.ToString(out.AccessKey.SecretAccessKey),
	}
}

// userWithKey creates a user with one access key.
func userWithKey(t *testing.T, c *iam.Client, name string) aws.Credentials {
	t.Helper()
	return createKey(t, c, createUser(t, c, name))
}

// callerIdentity calls GetCallerIdentity signed with creds.
func callerIdentity(
	t *testing.T,
	srv *server,
	creds aws.Credentials,
) (*sts.GetCallerIdentityOutput, error) {
	t.Helper()
	out, err := stsFor(srv, creds).GetCallerIdentity(t.Context(), &sts.GetCallerIdentityInput{})
	return out, err //nolint:wrapcheck // the test inspects the SDK's error as is
}

// rawResult is what a hand-signed request got back.
type rawResult struct {
	Code   string
	Body   string
	Status int
}

// queryError is the Query protocol's error envelope.
type queryError struct {
	XMLName xml.Name `xml:"ErrorResponse"`
	Error   struct {
		Type    string `xml:"Type"`
		Code    string `xml:"Code"`
		Message string `xml:"Message"`
	} `xml:"Error"`
}

// rawCall POSTs form to srv, signed with creds for service, the way the
// Query protocol SDKs send it. It is for requests no SDK client sends: an
// Action the client does not have, or one signed for the other service.
func rawCall(
	t *testing.T,
	srv *server,
	service string,
	creds aws.Credentials,
	form url.Values,
) rawResult {
	t.Helper()

	body := form.Encode()
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, srv.URL+"/",
		strings.NewReader(body))
	requireNoErr(t, err, "build request")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=utf-8")

	sum := sha256.Sum256([]byte(body))
	err = v4.NewSigner().SignHTTP(t.Context(), creds, req, hex.EncodeToString(sum[:]),
		service, signingRegion, time.Now())
	requireNoErr(t, err, "sign request")

	return doRaw(t, srv, req)
}

func doRaw(t *testing.T, srv *server, req *http.Request) rawResult {
	t.Helper()

	res, err := srv.Client().Do(req)
	requireNoErr(t, err, "send request")
	defer func() { _ = res.Body.Close() }()

	b, err := io.ReadAll(res.Body)
	requireNoErr(t, err, "read response")

	out := rawResult{Status: res.StatusCode, Body: string(b)}
	var env queryError
	if xml.Unmarshal(b, &env) == nil {
		out.Code = env.Error.Code
	}
	return out
}

// requireRawCode fails unless r is an error response with the given status
// and code.
func requireRawCode(t *testing.T, r rawResult, status int, code string) {
	t.Helper()
	if r.Status != status || r.Code != code {
		t.Fatalf("got status %d code %q, want %d %q; body: %s",
			r.Status, r.Code, status, code, r.Body)
	}
}

// errOf returns the error of an SDK call and drops its output, for tests that
// call an operation only for the error it reports.
func errOf[T any](_ T, err error) error {
	return err
}

func requireNoErr(t *testing.T, err error, what string) {
	t.Helper()
	if err != nil {
		t.Fatalf("%s: %v", what, err)
	}
}

func requireEqual[T comparable](t *testing.T, got, want T, what string) {
	t.Helper()
	if got != want {
		t.Fatalf("%s: got %v, want %v", what, got, want)
	}
}

func requireMatch(t *testing.T, re *regexp.Regexp, got, what string) {
	t.Helper()
	if !re.MatchString(got) {
		t.Fatalf("%s: %q does not match %s", what, got, re)
	}
}

// requireRecent fails unless ts is set and within a minute of the window
// [from, to], which allows for a store that keeps whole seconds.
func requireRecent(t *testing.T, ts *time.Time, from, to time.Time, what string) {
	t.Helper()
	if ts == nil {
		t.Fatalf("%s: not set", what)
	}
	if ts.Before(from.Add(-time.Minute)) || ts.After(to.Add(time.Minute)) {
		t.Fatalf("%s: %v is not between %v and %v", what, *ts, from, to)
	}
}

// requireCode fails unless err is an API error with the given error code.
func requireCode(t *testing.T, err error, code string) {
	t.Helper()
	var apiErr smithy.APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("want API error %s, got %v", code, err)
	}
	if apiErr.ErrorCode() != code {
		t.Fatalf("want error code %s, got %s (%v)", code, apiErr.ErrorCode(), err)
	}
}

// requireAs fails unless err matches the modeled SDK error type T.
func requireAs[T error](t *testing.T, err error) {
	t.Helper()
	var want T
	if !errors.As(err, &want) {
		t.Fatalf("want error of type %T, got %v", want, err)
	}
}

// Error codes the SDKs do not model as types.
const (
	// ValidationError is the common error for input that fails the model's
	// constraints: a length, a pattern, a range (IAM and STS Common Error
	// Types, HTTP 400).
	codeValidation = "ValidationError"

	// AccessDenied is IAM's and STS's answer to a principal that may not call
	// an operation, as the IAM User Guide's "Troubleshoot access denied error
	// messages" quotes it ("An error occurred (AccessDenied) when calling
	// ..."). The spec has identity answer non-admin IAM calls in this shape.
	codeAccessDenied = "AccessDenied"

	// InvalidClientTokenId, "The security token included in the request is
	// invalid", is what the Query protocol services send for an access key
	// they do not know, one that is not active, or a session token that is
	// not the key's (the sigv4 library's README, which identity's verifier
	// maps from). Assumption: the current IAM and STS Common Error Types
	// pages list only UnrecognizedClientException for an unknown key, but
	// the AWS CLI and SDKs report InvalidClientTokenId from IAM and STS.
	codeInvalidClientToken = "InvalidClientTokenId"

	// SignatureDoesNotMatch, HTTP 403, is a signature the service computes
	// differently (IAM User Guide, "Troubleshoot Signature Version 4 signing
	// for AWS API requests").
	codeSignatureMismatch = "SignatureDoesNotMatch"

	// MissingAuthenticationToken, HTTP 403, is a request with no credentials
	// (Common Error Types).
	codeMissingAuth = "MissingAuthenticationToken"

	// InvalidAction is the Query protocol's answer to an Action the service
	// does not have. Assumption: the current Common Error Types pages no
	// longer list it; it is the code IAM and STS send ("The action X is not
	// valid for this web service"), and what the spec's "unknown operation"
	// means for a Query service.
	codeInvalidAction = "InvalidAction"
)
