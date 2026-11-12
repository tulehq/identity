package app

import (
	"errors"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awshttp "github.com/aws/aws-sdk-go-v2/aws/transport/http"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

// requireStatus fails unless err is an SDK error with the HTTP status.
func requireStatus(t *testing.T, err error, status int) {
	t.Helper()
	var re *awshttp.ResponseError
	check(t, errors.As(err, &re) && re.HTTPStatusCode() == status,
		"got %v, want status %d", err, status)
}

func TestTheManagementAccountComesFromTheAccountsService(t *testing.T) {
	ctx := t.Context()

	// The accounts service's organization is managed by another account than
	// the root user's: a misconfiguration, reported as such.
	url := startApp(t, t.TempDir(), map[string]string{
		"TULE_Identity_AccountsEndpoint": fakeAccounts(t, "111111111111", member),
	})
	_, err := stsClient(url, rootCreds()).AssumeRole(ctx, &sts.AssumeRoleInput{
		RoleArn: aws.String(memberRole), RoleSessionName: aws.String("e2e"),
	})
	requireCode(t, err, "InternalFailure")
	requireStatus(t, err, http.StatusInternalServerError)

	// The management account, per the accounts service, has no role to
	// assume, though it is an active member.
	url = startApp(t, t.TempDir(), map[string]string{
		"TULE_Identity_AccountsEndpoint": fakeAccounts(t, defaultAccount, member),
	})
	_, err = stsClient(url, rootCreds()).AssumeRole(ctx, &sts.AssumeRoleInput{
		RoleArn: aws.String(
			"arn:aws:iam::" + defaultAccount + ":role/OrganizationAccountAccessRole"),
		RoleSessionName: aws.String("e2e"),
	})
	requireCode(t, err, "AccessDenied")
}

// testClock is a clock a test moves forward. The server reads it from its
// own goroutines.
type testClock struct {
	mu     sync.Mutex
	offset time.Duration
}

func (c *testClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return time.Now().Add(c.offset)
}

func (c *testClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.offset += d
}

func TestAnExpiredSessionGetsExpiredToken(t *testing.T) {
	ctx := t.Context()
	clock := &testClock{}
	url, out := assumeMemberRoleAt(t, clock.now)
	session := aws.Credentials{
		AccessKeyID:     aws.ToString(out.Credentials.AccessKeyId),
		SecretAccessKey: aws.ToString(out.Credentials.SecretAccessKey),
		SessionToken:    aws.ToString(out.Credentials.SessionToken),
	}
	_, err := stsClient(url, session).GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	check(t, err == nil, "get caller identity before expiry: %v", err)

	// Past the session's 15 minutes by the store's clock; the request is
	// still dated now, within the verifier's clock skew.
	clock.advance(15*time.Minute + time.Second)

	_, err = stsClient(url, session).GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	requireCode(t, err, "ExpiredToken")
	requireStatus(t, err, http.StatusForbidden)

	_, err = iamClient(url, session).ListUsers(ctx, &iam.ListUsersInput{})
	requireCode(t, err, "ExpiredToken")
	requireStatus(t, err, http.StatusForbidden)
}
