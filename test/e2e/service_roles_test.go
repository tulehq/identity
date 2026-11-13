//go:build e2e

package e2e

import (
	"errors"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/sts"

	"tule.dev/identity/servicerole"
)

// serviceRoleClient returns an assume-role client for srv, signed with creds.
func serviceRoleClient(t *testing.T, srv *server, creds aws.Credentials) *servicerole.Client {
	t.Helper()
	c, err := servicerole.New(servicerole.Config{
		HTTPClient:      srv.Client(),
		Endpoint:        srv.URL,
		AccessKeyID:     creds.AccessKeyID,
		SecretAccessKey: creds.SecretAccessKey,
	})
	requireNoErr(t, err, "new service role client")
	return c
}

func TestAFunctionAssumesItsExecutionRole(t *testing.T) {
	// The Lambda Developer Guide's execution role trust policy: the role
	// trusts lambda.amazonaws.com to call sts:AssumeRole.
	srv, root := rootIAM(t)
	createRole(t, root, "fn-exec", `{"Version":"2012-10-17","Statement":[{"Effect":"Allow",`+
		`"Principal":{"Service":"lambda.amazonaws.com"},"Action":"sts:AssumeRole"}]}`)
	putRolePolicy(t, root, "fn-exec", "list", policyDoc(allow("iam:ListRoles", "*")))
	c := serviceRoleClient(t, srv, rootCreds())

	s, err := c.AssumeServiceRole(t.Context(), iamRoleARN(defaultAccountID, "/", "fn-exec"),
		"invocation", "lambda.amazonaws.com", 15*time.Minute)
	requireNoErr(t, err, "assume the execution role")
	requireEqual(t, s.AssumedRoleUser.Arn,
		"arn:aws:sts::"+defaultAccountID+":assumed-role/fn-exec/invocation", "Arn")
	exp := s.Credentials.Expiration
	requireRecent(t, &exp, time.Now().Add(14*time.Minute), time.Now().Add(16*time.Minute),
		"Expiration")

	// The session has the role's permissions.
	creds := aws.Credentials{
		AccessKeyID:     s.Credentials.AccessKeyID,
		SecretAccessKey: s.Credentials.SecretAccessKey,
		SessionToken:    s.Credentials.SessionToken,
	}
	id, err := stsFor(srv, creds).GetCallerIdentity(t.Context(), &sts.GetCallerIdentityInput{})
	requireNoErr(t, err, "get caller identity as the session")
	requireEqual(t, aws.ToString(id.Arn), s.AssumedRoleUser.Arn, "caller Arn")
	requireNoErr(t, errOf(iamFor(srv, creds).ListRoles(t.Context(), &iam.ListRolesInput{})),
		"list roles as the session")
	requireCode(t, errOf(iamFor(srv, creds).ListUsers(t.Context(), &iam.ListUsersInput{})),
		codeAccessDenied)

	// Another service is not trusted, a missing role is told apart, and
	// only the root key may ask.
	_, err = c.AssumeServiceRole(t.Context(), iamRoleARN(defaultAccountID, "/", "fn-exec"),
		"invocation", "ecs-tasks.amazonaws.com", 0)
	if !errors.Is(err, servicerole.ErrNotTrusted) {
		t.Fatalf("another service: got %v, want %v", err, servicerole.ErrNotTrusted)
	}
	_, err = c.AssumeServiceRole(t.Context(), iamRoleARN(defaultAccountID, "/", "missing"),
		"invocation", "lambda.amazonaws.com", 0)
	if !errors.Is(err, servicerole.ErrNoSuchRole) {
		t.Fatalf("missing role: got %v, want %v", err, servicerole.ErrNoSuchRole)
	}
	user := userWithKey(t, root, "dev")
	_, err = serviceRoleClient(t, srv, user).AssumeServiceRole(t.Context(),
		iamRoleARN(defaultAccountID, "/", "fn-exec"), "invocation", "lambda.amazonaws.com", 0)
	var e *servicerole.Error
	if !errors.As(err, &e) || e.Status != 403 {
		t.Fatalf("user key: got %v, want a 403 *servicerole.Error", err)
	}
}
