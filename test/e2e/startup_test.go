//go:build e2e

package e2e

import (
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

// The API versions of the two Query APIs (the spec's Contract).
const (
	iamVersion = "2010-05-08"
	stsVersion = "2011-06-15"
)

func TestProbesNeedNoCredentials(t *testing.T) {
	srv := startServer(t, nil)

	for _, path := range []string{"/_health", "/_ready"} {
		req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, srv.URL+path, nil)
		requireNoErr(t, err, "build request")

		res, err := srv.Client().Do(req)
		requireNoErr(t, err, "probe "+path)
		_ = res.Body.Close()
		requireEqual(t, res.StatusCode, http.StatusOK, "unsigned "+path)
	}
}

func TestUnsignedRequestIsRejected(t *testing.T) {
	// MissingAuthenticationToken, HTTP 403 (Common Error Types).
	srv := startServer(t, nil)

	for service, form := range map[string]url.Values{
		"sts": {"Action": {"GetCallerIdentity"}, "Version": {stsVersion}},
		"iam": {"Action": {"ListUsers"}, "Version": {iamVersion}},
	} {
		t.Run(service, func(t *testing.T) {
			req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, srv.URL+"/",
				strings.NewReader(form.Encode()))
			requireNoErr(t, err, "build request")
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			requireRawCode(t, doRaw(t, srv, req), http.StatusForbidden, codeMissingAuth)
		})
	}
}

func TestWrongCredentialsAreRejected(t *testing.T) {
	srv, c := rootIAM(t)
	key := userWithKey(t, c, "dev")

	tests := []struct {
		creds aws.Credentials
		name  string
		code  string
	}{
		{
			name:  "root key, wrong secret",
			creds: aws.Credentials{AccessKeyID: rootKeyID, SecretAccessKey: "wrong"},
			code:  codeSignatureMismatch,
		},
		{
			name:  "user key, wrong secret",
			creds: aws.Credentials{AccessKeyID: key.AccessKeyID, SecretAccessKey: "wrong"},
			code:  codeSignatureMismatch,
		},
		{
			name:  "unknown key",
			creds: aws.Credentials{AccessKeyID: unknownKeyID, SecretAccessKey: rootSecret},
			code:  codeInvalidClientToken,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name+" on sts", func(t *testing.T) {
			requireCode(t, errOf(callerIdentity(t, srv, tt.creds)), tt.code)
		})
		t.Run(tt.name+" on iam", func(t *testing.T) {
			err := errOf(iamFor(srv, tt.creds).CreateUser(t.Context(), &iam.CreateUserInput{
				UserName: aws.String("intruder"),
			}))
			requireCode(t, err, tt.code)
		})
	}

	// No refused request created anything.
	out, err := c.ListUsers(t.Context(), &iam.ListUsersInput{})
	requireNoErr(t, err, "list users")
	requireSameNames(t, userNames(out.Users), []string{"dev"})
}

func TestUnknownOperations(t *testing.T) {
	// The spec: one server serves both APIs and tells them apart by the
	// credential scope's service, and an Action that does not belong to that
	// service is an unknown operation, InvalidAction (HTTP 400) in the Query
	// protocol.
	srv := startServer(t, nil)
	root := rootCreds()

	tests := []struct {
		form    url.Values
		name    string
		service string
	}{
		{url.Values{"Action": {"Nonsense"}, "Version": {iamVersion}}, "nonsense on iam", "iam"},
		{url.Values{"Action": {"Nonsense"}, "Version": {stsVersion}}, "nonsense on sts", "sts"},
		{url.Values{
			"Action": {"ListUsers"}, "Version": {iamVersion},
		}, "ListUsers signed for sts", "sts"},
		{url.Values{
			"Action": {"CreateUser"}, "Version": {iamVersion}, "UserName": {"crossed"},
		}, "CreateUser signed for sts", "sts"},
		{url.Values{
			"Action": {"GetCallerIdentity"}, "Version": {stsVersion},
		}, "GetCallerIdentity signed for iam", "iam"},
		{url.Values{
			"Action":          {"AssumeRole"},
			"Version":         {stsVersion},
			"RoleArn":         {roleARN("123456789012")},
			"RoleSessionName": {"crossed"},
		}, "AssumeRole signed for iam", "iam"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := rawCall(t, srv, tt.service, root, tt.form)
			requireRawCode(t, r, http.StatusBadRequest, codeInvalidAction)
		})
	}

	// The crossed CreateUser created nothing.
	_, err := iamFor(srv, root).GetUser(t.Context(), &iam.GetUserInput{
		UserName: aws.String("crossed"),
	})
	requireCode(t, err, "NoSuchEntity")
}

func TestOutOfScopeOperations(t *testing.T) {
	// Assumption: an operation the spec puts out of scope answers as an
	// unknown one, as accounts does for its out-of-scope operations.
	srv := startServer(t, nil)
	root := rootCreds()

	t.Run("iam ListRoles", func(t *testing.T) {
		err := errOf(iamFor(srv, root).ListRoles(t.Context(), &iam.ListRolesInput{}))
		requireCode(t, err, codeInvalidAction)
	})
	t.Run("iam CreateGroup", func(t *testing.T) {
		err := errOf(iamFor(srv, root).CreateGroup(t.Context(), &iam.CreateGroupInput{
			GroupName: aws.String("g"),
		}))
		requireCode(t, err, codeInvalidAction)
	})
	t.Run("sts GetSessionToken", func(t *testing.T) {
		err := errOf(stsFor(srv, root).GetSessionToken(t.Context(), &sts.GetSessionTokenInput{}))
		requireCode(t, err, codeInvalidAction)
	})

	// The service is still up.
	_, err := callerIdentity(t, srv, root)
	requireNoErr(t, err, "get caller identity after unsupported calls")
}

func TestDataSurvivesRestart(t *testing.T) {
	env := map[string]string{"TULE_Store_Path": filepath.Join(t.TempDir(), "identity.db")}

	first := startServer(t, env)
	c := iamFor(first, rootCreds())
	created, err := c.CreateUser(t.Context(), &iam.CreateUserInput{
		UserName: aws.String("persisted"), Path: aws.String("/team/"),
	})
	requireNoErr(t, err, "create user")
	active := createKey(t, c, "persisted")
	inactive := createKey(t, c, "persisted")
	setKeyStatus(t, c, "persisted", inactive.AccessKeyID, "Inactive")

	// The next process on the same file is what a restart looks like.
	first.Stop(t)
	srv := startServer(t, env)
	c = iamFor(srv, rootCreds())

	got, err := c.GetUser(t.Context(), &iam.GetUserInput{UserName: aws.String("persisted")})
	requireNoErr(t, err, "get user after restart")
	requireUser(t, got.User, defaultAccountID, "/team/", "persisted")
	requireEqual(t, aws.ToString(got.User.UserId), aws.ToString(created.User.UserId),
		"UserId after restart")

	requireEqual(t, len(listKeys(t, c, "persisted")), 2, "key count after restart")

	// The secret is kept, so the key still signs.
	out, err := callerIdentity(t, srv, active)
	requireNoErr(t, err, "get caller identity with the key after restart")
	requireEqual(t, aws.ToString(out.Arn), aws.ToString(created.User.Arn), "Arn after restart")

	requireCode(t, errOf(callerIdentity(t, srv, inactive)), codeInvalidClientToken)
}
