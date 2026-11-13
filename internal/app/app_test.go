package app

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/aws/smithy-go"
)

// The root user's key: the AWS documentation's example.
const (
	testKeyID  = "AKIAIOSFODNN7EXAMPLE"
	testSecret = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
)

// startApp starts the app on a store in dir, with env setting extra TULE_
// variables, and returns the URL of a server for its handler. The full
// server, over TCP, is what test/e2e drives; this only checks that the
// wiring, the protocol and the store meet as the SDKs expect.
func startApp(t *testing.T, dir string, env map[string]string) string {
	t.Helper()
	return startAppAt(t, dir, env, time.Now)
}

// startAppAt is startApp with the clock the store tells the time by.
func startAppAt(t *testing.T, dir string, env map[string]string, now func() time.Time) string {
	t.Helper()
	t.Setenv("TULE_Store_Path", filepath.Join(dir, "nested", "identity.db"))
	for k, v := range env {
		t.Setenv(k, v)
	}

	cfg, err := loadEnvConfig(t, testKeyID, testSecret)
	check(t, err == nil, "load config: %v", err)
	a, err := newApp(cfg, now)
	check(t, err == nil, "new app: %v", err)
	if err = a.Start(context.Background()); err != nil {
		t.Fatalf("start app: %v", err)
	}
	srv := httptest.NewServer(a.Handler())
	t.Cleanup(func() {
		srv.Close()
		if sErr := a.Shutdown(context.Background()); sErr != nil {
			t.Errorf("shutdown: %v", sErr)
		}
	})
	return srv.URL
}

func rootCreds() aws.Credentials {
	return aws.Credentials{AccessKeyID: testKeyID, SecretAccessKey: testSecret}
}

func iamClient(url string, c aws.Credentials) *iam.Client {
	return iam.New(iam.Options{
		Region:       "us-east-1",
		BaseEndpoint: aws.String(url),
		Credentials: credentials.NewStaticCredentialsProvider(
			c.AccessKeyID, c.SecretAccessKey, c.SessionToken),
		RetryMaxAttempts: 1,
	})
}

func stsClient(url string, c aws.Credentials) *sts.Client {
	return sts.New(sts.Options{
		Region:       "us-east-1",
		BaseEndpoint: aws.String(url),
		Credentials: credentials.NewStaticCredentialsProvider(
			c.AccessKeyID, c.SecretAccessKey, c.SessionToken),
		RetryMaxAttempts: 1,
	})
}

// check fails the test with the message unless ok.
func check(t *testing.T, ok bool, format string, args ...any) {
	t.Helper()
	if !ok {
		t.Fatalf(format, args...)
	}
}

func requireCode(t *testing.T, err error, code string) {
	t.Helper()
	var apiErr smithy.APIError
	check(
		t,
		errors.As(err, &apiErr) && apiErr.ErrorCode() == code,
		"got %v, want error code %s",
		err,
		code,
	)
}

// errorCode returns the Code of a Query error document.
func errorCode(t *testing.T, body []byte) string {
	t.Helper()
	var doc struct {
		Code string `xml:"Error>Code"`
	}
	if err := xml.Unmarshal(body, &doc); err != nil {
		t.Fatalf("decode error document %q: %v", body, err)
	}
	return doc.Code
}

// createUserWithKey creates a user and an access key for it as the root
// user, and returns the key.
func createUserWithKey(t *testing.T, c *iam.Client, name string) aws.Credentials {
	t.Helper()
	ctx := t.Context()
	if _, err := c.CreateUser(ctx, &iam.CreateUserInput{UserName: aws.String(name)}); err != nil {
		t.Fatalf("create user: %v", err)
	}
	out, err := c.CreateAccessKey(ctx, &iam.CreateAccessKeyInput{UserName: aws.String(name)})
	check(t, err == nil, "create access key: %v", err)
	return aws.Credentials{
		AccessKeyID:     aws.ToString(out.AccessKey.AccessKeyId),
		SecretAccessKey: aws.ToString(out.AccessKey.SecretAccessKey),
	}
}

func TestTheSDKsManageUsersAndKeys(t *testing.T) {
	ctx := t.Context()
	dir := t.TempDir()
	url := startApp(t, dir, nil)
	root := iamClient(url, rootCreds())

	created, err := root.CreateUser(ctx, &iam.CreateUserInput{
		UserName: aws.String("dev"), Path: aws.String("/team/"),
	})
	check(t, err == nil, "create user: %v", err)
	u := created.User
	check(
		t,
		aws.ToString(u.Arn) == "arn:aws:iam::000000000000:user/team/dev" &&
			u.CreateDate != nil && len(aws.ToString(u.UserId)) == 21,
		"user = %+v",
		u,
	)

	key, err := root.CreateAccessKey(ctx, &iam.CreateAccessKeyInput{UserName: aws.String("dev")})
	check(t, err == nil, "create access key: %v", err)
	check(
		t,
		key.AccessKey.Status == iamtypes.StatusTypeActive &&
			len(aws.ToString(key.AccessKey.SecretAccessKey)) == 40,
		"access key = %+v",
		key.AccessKey,
	)

	listed, err := root.ListAccessKeys(ctx, &iam.ListAccessKeysInput{UserName: aws.String("DEV")})
	check(t, err == nil, "list access keys: %v", err)
	check(t, len(listed.AccessKeyMetadata) == 1 && !listed.IsTruncated, "listed = %+v", listed)

	// An operation with no output decodes too.
	_, err = root.DeleteUser(ctx, &iam.DeleteUserInput{UserName: aws.String("dev")})
	requireCode(t, err, "DeleteConflict")
	if _, err = root.DeleteAccessKey(ctx, &iam.DeleteAccessKeyInput{
		UserName: aws.String("dev"), AccessKeyId: key.AccessKey.AccessKeyId,
	}); err != nil {
		t.Fatalf("delete access key: %v", err)
	}
	if _, err = root.DeleteUser(
		ctx,
		&iam.DeleteUserInput{UserName: aws.String("dev")},
	); err != nil {
		t.Fatalf("delete user: %v", err)
	}
	_, err = root.GetUser(ctx, &iam.GetUserInput{UserName: aws.String("dev")})
	var noSuch *iamtypes.NoSuchEntityException
	check(t, errors.As(err, &noSuch), "get deleted user = %v, want NoSuchEntityException", err)

	if _, err = os.Stat(filepath.Join(dir, "nested", "identity.db")); err != nil {
		t.Fatalf("store file: %v", err)
	}
}

func TestAUserKeySignsButIsNoAdmin(t *testing.T) {
	ctx := t.Context()
	url := startApp(t, t.TempDir(), nil)
	root := iamClient(url, rootCreds())
	key := createUserWithKey(t, root, "dev")

	me, err := stsClient(url, key).GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	check(t, err == nil, "get caller identity: %v", err)
	check(
		t,
		aws.ToString(me.Arn) == "arn:aws:iam::000000000000:user/dev",
		"caller = %s",
		aws.ToString(me.Arn),
	)

	_, err = iamClient(url, key).ListUsers(ctx, &iam.ListUsersInput{})
	requireCode(t, err, "AccessDenied")

	// The use was recorded, as STS, in the region the request was signed
	// for.
	used, err := root.GetAccessKeyLastUsed(ctx, &iam.GetAccessKeyLastUsedInput{
		AccessKeyId: aws.String(key.AccessKeyID),
	})
	check(t, err == nil, "get access key last used: %v", err)
	lu := used.AccessKeyLastUsed
	check(
		t,
		aws.ToString(used.UserName) == "dev" &&
			lu.LastUsedDate != nil &&
			aws.ToString(lu.ServiceName) == "iam" &&
			aws.ToString(lu.Region) == "us-east-1",
		"last used = %+v %+v",
		used,
		lu,
	)

	// Inactive, the key is refused as an invalid one.
	if _, err = root.UpdateAccessKey(ctx, &iam.UpdateAccessKeyInput{
		UserName: aws.String("dev"), AccessKeyId: aws.String(key.AccessKeyID),
		Status: iamtypes.StatusTypeInactive,
	}); err != nil {
		t.Fatalf("update access key: %v", err)
	}
	_, err = stsClient(url, key).GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	requireCode(t, err, "InvalidClientTokenId")
}

func TestANeverUsedKeyHasNoLastUse(t *testing.T) {
	ctx := t.Context()
	url := startApp(t, t.TempDir(), nil)
	root := iamClient(url, rootCreds())
	key := createUserWithKey(t, root, "dev")

	used, err := root.GetAccessKeyLastUsed(ctx, &iam.GetAccessKeyLastUsedInput{
		AccessKeyId: aws.String(key.AccessKeyID),
	})
	check(t, err == nil, "get access key last used: %v", err)
	lu := used.AccessKeyLastUsed
	check(
		t,
		lu.LastUsedDate == nil &&
			aws.ToString(lu.ServiceName) == "N/A" &&
			aws.ToString(lu.Region) == "N/A",
		"last used = %+v",
		lu,
	)
}

func TestAnIAMActionSignedForSTSIsInvalid(t *testing.T) {
	ctx := t.Context()
	url := startApp(t, t.TempDir(), nil)

	// An IAM operation signed for sts is not an STS operation.
	status, body := signedCall(t, url, "sts", "Action=ListUsers&Version=2010-05-08")
	check(
		t,
		status == http.StatusBadRequest &&
			errorCode(t, body) == "InvalidAction",
		"ListUsers signed for sts: status %d, body %s",
		status,
		body,
	)

	// An IAM operation this service leaves out.
	_, err := iamClient(url, rootCreds()).ListGroups(ctx, &iam.ListGroupsInput{})
	requireCode(t, err, "InvalidAction")
}

// fakeAccounts serves DescribeOrganization and DescribeAccount as the
// accounts service does, for an organization managed by management whose
// active members are management and the accounts given. It does not verify
// signatures.
func fakeAccounts(t *testing.T, management string, active ...string) string {
	t.Helper()
	members := append([]string{management}, active...)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/x-amz-json-1.1")
		switch r.Header.Get("X-Amz-Target") {
		case "AWSOrganizationsV20161128.DescribeOrganization":
			_ = json.NewEncoder(w).Encode(map[string]any{"Organization": map[string]string{
				"Id": "o-exampleorg1", "MasterAccountId": management, "FeatureSet": "ALL",
			}})
		case "AWSOrganizationsV20161128.DescribeAccount":
			var in struct {
				AccountID string `json:"AccountId"`
			}
			if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
				http.Error(w, "unexpected body", http.StatusBadRequest)
				return
			}
			if slices.Contains(members, in.AccountID) {
				_ = json.NewEncoder(w).Encode(map[string]any{"Account": map[string]string{
					"Id": in.AccountID, "State": "ACTIVE", "Status": "ACTIVE",
				}})
				return
			}
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]string{
				"__type": "AccountNotFoundException", "Message": "not found",
			})
		default:
			http.Error(w, "unexpected request", http.StatusBadRequest)
		}
	}))
	t.Cleanup(srv.Close)
	return srv.URL
}

// memberRole is OrganizationAccountAccessRole in the fake organization's
// member account; defaultAccount manages it, as TULE_Identity_AccountID does
// by default.
const (
	defaultAccount = "000000000000"
	member         = "123456789012"
	memberRole     = "arn:aws:iam::" + member + ":role/OrganizationAccountAccessRole"
)

// assumeMemberRole starts the app with an accounts service that knows the
// member account and assumes its role as the root user.
func assumeMemberRole(t *testing.T) (string, *sts.AssumeRoleOutput) {
	t.Helper()
	return assumeMemberRoleAt(t, time.Now)
}

// assumeMemberRoleAt is assumeMemberRole with the store's clock.
func assumeMemberRoleAt(t *testing.T, now func() time.Time) (string, *sts.AssumeRoleOutput) {
	t.Helper()
	url := startAppAt(t, t.TempDir(), map[string]string{
		"TULE_Identity_AccountsEndpoint": fakeAccounts(t, defaultAccount, member),
	}, now)
	out, err := stsClient(url, rootCreds()).AssumeRole(t.Context(), &sts.AssumeRoleInput{
		RoleArn:         aws.String(memberRole),
		RoleSessionName: aws.String("e2e"),
		DurationSeconds: aws.Int32(900),
	})
	check(t, err == nil, "assume role: %v", err)
	return url, out
}

func TestAssumeRoleIntoAnActiveMemberAccount(t *testing.T) {
	ctx := t.Context()
	url, out := assumeMemberRole(t)
	wantARN := "arn:aws:sts::" + member + ":assumed-role/OrganizationAccountAccessRole/e2e"
	check(t, aws.ToString(out.AssumedRoleUser.Arn) == wantARN,
		"assumed role ARN = %s", aws.ToString(out.AssumedRoleUser.Arn))
	d := time.Until(aws.ToTime(out.Credentials.Expiration))
	check(t, d <= 15*time.Minute && d > 14*time.Minute, "expires in %s, want 15m", d)

	session := aws.Credentials{
		AccessKeyID:     aws.ToString(out.Credentials.AccessKeyId),
		SecretAccessKey: aws.ToString(out.Credentials.SecretAccessKey),
		SessionToken:    aws.ToString(out.Credentials.SessionToken),
	}
	me, err := stsClient(url, session).GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	check(t, err == nil, "get caller identity: %v", err)
	check(t, aws.ToString(me.Arn) == wantARN && aws.ToString(me.Account) == member &&
		aws.ToString(me.UserId) == aws.ToString(out.AssumedRoleUser.AssumedRoleId),
		"caller = %+v", me)

	// The session is an admin of the member account.
	created, err := iamClient(url, session).CreateUser(ctx, &iam.CreateUserInput{
		UserName: aws.String("dev"),
	})
	check(t, err == nil, "create user in the member account: %v", err)
	check(t, aws.ToString(created.User.Arn) == "arn:aws:iam::"+member+":user/dev",
		"user ARN = %s", aws.ToString(created.User.Arn))

	// Without its token, the session's key is unknown.
	session.SessionToken = ""
	_, err = stsClient(url, session).GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	requireCode(t, err, "InvalidClientTokenId")
}

func TestAssumeRoleRefusals(t *testing.T) {
	url, _ := assumeMemberRole(t)
	rootSTS := stsClient(url, rootCreds())

	// An account the organization does not have has no role to assume.
	_, err := rootSTS.AssumeRole(t.Context(), &sts.AssumeRoleInput{
		RoleArn:         aws.String("arn:aws:iam::210987654321:role/OrganizationAccountAccessRole"),
		RoleSessionName: aws.String("e2e"),
	})
	requireCode(t, err, "AccessDenied")

	// The role's maximum session is an hour.
	_, err = rootSTS.AssumeRole(t.Context(), &sts.AssumeRoleInput{
		RoleArn:         aws.String(memberRole),
		RoleSessionName: aws.String("e2e"),
		DurationSeconds: aws.Int32(3601),
	})
	requireCode(t, err, "ValidationError")
}

// signedCall posts form, signed with the root key for service, and returns
// the response's status and body.
func signedCall(t *testing.T, url, service, form string) (int, []byte) {
	t.Helper()
	return signedCallAs(t, url, service, form, rootCreds())
}

// signedCallAs is signedCall signed with creds.
func signedCallAs(
	t *testing.T,
	url, service, form string,
	creds aws.Credentials,
) (int, []byte) {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, url+"/",
		strings.NewReader(form))
	check(t, err == nil, "new request: %v", err)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	sum := sha256.Sum256([]byte(form))
	if err = v4.NewSigner().SignHTTP(t.Context(), creds, req,
		hex.EncodeToString(sum[:]), service, "us-east-1", time.Now()); err != nil {
		t.Fatalf("sign: %v", err)
	}
	resp, err := http.DefaultClient.Do(req)
	check(t, err == nil, "post: %v", err)
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	check(t, err == nil, "read body: %v", err)
	return resp.StatusCode, body
}

func TestAnUnsignedRequestIsRefused(t *testing.T) {
	url := startApp(t, t.TempDir(), nil)

	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, url+"/",
		strings.NewReader("Action=GetCallerIdentity&Version=2011-06-15"))
	check(t, err == nil, "new request: %v", err)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := http.DefaultClient.Do(req)
	check(t, err == nil, "post: %v", err)
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	check(t, err == nil, "read body: %v", err)
	check(
		t,
		resp.StatusCode == http.StatusForbidden &&
			errorCode(t, body) == "MissingAuthenticationToken",
		"status %d, body %s",
		resp.StatusCode,
		body,
	)
}
