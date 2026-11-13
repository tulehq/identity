//go:build e2e

package e2e

import (
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

// assumeAs calls AssumeRole signed with creds.
func assumeAs(
	t *testing.T,
	srv *server,
	creds aws.Credentials,
	role, session string,
	duration *int32,
) (*sts.AssumeRoleOutput, error) {
	t.Helper()
	out, err := stsFor(srv, creds).AssumeRole(t.Context(), &sts.AssumeRoleInput{
		RoleArn:         aws.String(role),
		RoleSessionName: aws.String(session),
		DurationSeconds: duration,
	})
	return out, err //nolint:wrapcheck // the test inspects the SDK's error as is
}

// mustAssume is assumeAs that fails the test on an error.
func mustAssume(
	t *testing.T,
	srv *server,
	creds aws.Credentials,
	role, session string,
) *sts.AssumeRoleOutput {
	t.Helper()
	out, err := assumeAs(t, srv, creds, role, session, nil)
	requireNoErr(t, err, "assume "+role)
	if out.Credentials == nil || out.AssumedRoleUser == nil {
		t.Fatalf("assume %s returned no credentials or no AssumedRoleUser", role)
	}
	return out
}

// requireAssumeDenied fails unless err is AWS's AccessDenied for caller's
// sts:AssumeRole, in the message form of "Troubleshoot access denied error
// messages" ("User: <arn> is not authorized to perform: sts:AssumeRole").
// The rest of the message differs between a trust policy and an identity
// policy denying, so it is not checked.
func requireAssumeDenied(t *testing.T, err error, caller string) {
	t.Helper()
	requireCode(t, err, codeAccessDenied)
	requireMessageContains(t, err,
		"User: "+caller+" is not authorized to perform: sts:AssumeRole")
}

// sessionARN is a session's ARN, arn:aws:sts::<account>:assumed-role/<role
// name>/<session> (IAM identifiers).
func sessionARN(account, role, session string) string {
	return "arn:aws:sts::" + account + ":assumed-role/" + role + "/" + session
}

// canAssume allows sts:AssumeRole on the role ARN.
func canAssume(role string) string {
	return policyDoc(allow("sts:AssumeRole", role))
}

func TestAssumeRoleTrustedUser(t *testing.T) {
	srv, c := rootIAM(t)
	createUser(t, c, "dev")
	trusted := iamRoleARN(defaultAccountID, "/", "Trusted")
	byAccount := iamRoleARN(defaultAccountID, "/", "ByAccount")
	byID := iamRoleARN(defaultAccountID, "/", "ByAccountID")
	createRole(t, c, "Trusted", trustDoc(devARN("dev")))
	// "When you specify an AWS account, you can use the account ARN
	// (arn:aws:iam::account-ID:root), or a shortened form ... the account
	// ID"; both "delegate permissions to the account".
	createRole(t, c, "ByAccount", trustDoc(rootARN(defaultAccountID)))
	createRole(t, c, "ByAccountID", trustDoc(defaultAccountID))
	putUserPolicy(t, c, "dev", "assume", policyDoc(allow("sts:AssumeRole",
		[]string{trusted, byAccount, byID})))
	key := createKey(t, c, "dev")

	for _, role := range []string{trusted, byAccount, byID} {
		t.Run(role, func(t *testing.T) {
			before := time.Now()
			out := mustAssume(t, srv, key, role, "dev-session")
			name := role[strings.LastIndex(role, "/")+1:]
			requireEqual(t, aws.ToString(out.AssumedRoleUser.Arn),
				sessionARN(defaultAccountID, name, "dev-session"), "Arn")
			requireMatch(t, tempKeyPattern, aws.ToString(out.Credentials.AccessKeyId),
				"AccessKeyId")
			requireRecent(t, out.Credentials.Expiration, before.Add(time.Hour),
				time.Now().Add(time.Hour), "Expiration")
			id, err := callerIdentity(t, srv, sessionCreds(out))
			requireNoErr(t, err, "get caller identity with the session")
			requireEqual(t, aws.ToString(id.Arn), aws.ToString(out.AssumedRoleUser.Arn),
				"caller Arn")
		})
	}
}

func TestAssumeRoleNeedsIdentityPolicy(t *testing.T) {
	// AssumeRole (STS API reference, Permissions): in the same account a
	// user may assume a role either through "a policy to the user that
	// allows the user to call AssumeRole (as long as the role's trust policy
	// trusts the account)", or by being added "as a principal directly in
	// the role's trust policy", because "When a resource-based policy grants
	// access to a principal in the same account, no additional
	// identity-based policy is required". So with no identity policy, a
	// trust policy naming only the account denies, and one naming the user
	// allows.
	srv, c := rootIAM(t)
	createUser(t, c, "dev")
	key := createKey(t, c, "dev")
	byAccount := iamRoleARN(defaultAccountID, "/", "ByAccount")
	createRole(t, c, "ByAccount", trustDoc(rootARN(defaultAccountID)))
	createRole(t, c, "ByUser", trustDoc(devARN("dev")))
	createRole(t, c, "ByAnyone", trustDoc("*"))

	t.Run("ByAccount", func(t *testing.T) {
		_, err := assumeAs(t, srv, key, byAccount, "sess", nil)
		requireAssumeDenied(t, err, devARN("dev"))
	})
	t.Run("ByUser", func(t *testing.T) {
		out := mustAssume(t, srv, key, iamRoleARN(defaultAccountID, "/", "ByUser"), "sess")
		requireEqual(t, aws.ToString(out.AssumedRoleUser.Arn),
			sessionARN(defaultAccountID, "ByUser", "sess"), "Arn")
	})
	// Principal element, All principals: with "*" in a resource-based
	// policy, "For IAM users and role principals within your account, no
	// other permissions are required."
	t.Run("ByAnyone", func(t *testing.T) {
		mustAssume(t, srv, key, iamRoleARN(defaultAccountID, "/", "ByAnyone"), "sess")
	})

	// A policy allowing sts:AssumeRole on another role does not help with
	// the account-trusted one; one allowing it on that role does
	// (TestAssumeRoleTrustedUser).
	t.Run("ByAccount with a policy on another role only", func(t *testing.T) {
		putUserPolicy(t, c, "dev", "assume",
			canAssume(iamRoleARN(defaultAccountID, "/", "ByUser")))
		_, err := assumeAs(t, srv, key, byAccount, "sess", nil)
		requireAssumeDenied(t, err, devARN("dev"))
	})
}

func TestAssumeRoleUntrustedCaller(t *testing.T) {
	// A trust policy that does not name the caller, its account, or "*"
	// does not allow it, whatever the caller's own policies allow.
	srv, c := rootIAM(t)
	createUser(t, c, "someone-else")
	createRole(t, c, "Private", trustDoc(devARN("someone-else")))
	createRole(t, c, "Foreign", trustDoc(rootARN("123456789012")))
	key := userWithPolicy(t, c, "dev", policyDoc(allow("sts:AssumeRole", "*")))

	for _, name := range []string{"Private", "Foreign"} {
		t.Run(name, func(t *testing.T) {
			_, err := assumeAs(t, srv, key, iamRoleARN(defaultAccountID, "/", name), "sess", nil)
			requireAssumeDenied(t, err, devARN("dev"))
		})
	}

	// Assumption: as for OrganizationAccountAccessRole, a role that does not
	// exist is AccessDenied, indistinguishable from one the caller may not
	// assume.
	t.Run("no such role", func(t *testing.T) {
		_, err := assumeAs(t, srv, key, iamRoleARN(defaultAccountID, "/", "Nope"), "sess", nil)
		requireCode(t, err, codeAccessDenied)
	})
}

func TestAssumeRoleDuration(t *testing.T) {
	// DurationSeconds: "from 900 seconds (15 minutes) up to the maximum
	// session duration set for the role ... If you specify a value higher
	// than this setting ..., the operation fails." Assumption, as in
	// testDurationSeconds: the failure is ValidationError.
	srv, c := rootIAM(t)
	role := iamRoleARN(defaultAccountID, "/", "Long")
	_, err := c.CreateRole(t.Context(), &iam.CreateRoleInput{
		RoleName:                 aws.String("Long"),
		AssumeRolePolicyDocument: aws.String(trustDoc(rootARN(defaultAccountID))),
		MaxSessionDuration:       aws.Int32(7200),
	})
	requireNoErr(t, err, "create role")
	key := userWithPolicy(t, c, "dev", canAssume(role))

	for _, d := range []int32{900, 7200} {
		t.Run(strconv.Itoa(int(d)), func(t *testing.T) {
			before := time.Now()
			out, err := assumeAs(t, srv, key, role, "dur", aws.Int32(d))
			requireNoErr(t, err, "assume role")
			span := time.Duration(d) * time.Second
			requireRecent(t, out.Credentials.Expiration, before.Add(span),
				time.Now().Add(span), "Expiration")
		})
	}
	t.Run("7201", func(t *testing.T) {
		_, err := assumeAs(t, srv, key, role, "dur", aws.Int32(7201))
		requireCode(t, err, codeValidation)
	})

	// MaxSessionDuration "determines the maximum duration that can be
	// requested", so lowering it takes 7200 away.
	t.Run("after UpdateRole lowers the maximum", func(t *testing.T) {
		_, err := c.UpdateRole(t.Context(), &iam.UpdateRoleInput{
			RoleName: aws.String("Long"), MaxSessionDuration: aws.Int32(3600),
		})
		requireNoErr(t, err, "update role")
		_, err = assumeAs(t, srv, key, role, "dur", aws.Int32(7200))
		requireCode(t, err, codeValidation)
	})
}

func TestSessionHasRolePermissions(t *testing.T) {
	// "When a principal or identity assumes a role, they receive temporary
	// security credentials with the assumed role's permissions" (Principal
	// element, IAM role principals): the session has the role's policies,
	// not its caller's. The caller here is an administrator, the role may
	// only list users.
	srv, c := rootIAM(t)
	role := iamRoleARN(defaultAccountID, "/", "Lister")
	createRole(t, c, "Lister", trustDoc(rootARN(defaultAccountID)))
	putRolePolicy(t, c, "Lister", "list", policyDoc(allow("iam:ListUsers", "*")))
	createUser(t, c, "boss")
	attachUserPolicy(t, c, "boss", adminAccessARN)
	sess := sessionCreds(mustAssume(t, srv, createKey(t, c, "boss"), role, "work"))
	sc := iamFor(srv, sess)

	_, err := sc.ListUsers(t.Context(), &iam.ListUsersInput{})
	requireNoErr(t, err, "list users with the session")

	err = errOf(sc.CreateUser(t.Context(), &iam.CreateUserInput{UserName: aws.String("x")}))
	requireCode(t, err, codeAccessDenied)
	requireMessageContains(t, err, "is not authorized to perform: iam:CreateUser")

	t.Run("attached managed policy counts", func(t *testing.T) {
		attachRolePolicy(t, c, "Lister", createPolicy(t, c, "Maker",
			policyDoc(allow("iam:CreateUser", "*"))))
		s := sessionCreds(mustAssume(t, srv, createKey(t, c, "boss"), role, "work2"))
		createUser(t, iamFor(srv, s), "made-by-session")
	})

	t.Run("GetCallerIdentity", func(t *testing.T) {
		_, err := callerIdentity(t, srv, sess)
		requireNoErr(t, err, "get caller identity with the session")
	})
}

func requireMessageContains(t *testing.T, err error, want string) {
	t.Helper()
	if err == nil || !strings.Contains(err.Error(), want) {
		t.Fatalf("error %v does not contain %q", err, want)
	}
}
