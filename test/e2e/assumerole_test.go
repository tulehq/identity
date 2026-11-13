//go:build e2e

package e2e

import (
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

// assumedRoleARN is a role session's ARN (the spec, and the IAM User Guide's
// IAM identifiers: arn:aws:sts::<account>:assumed-role/<role>/<session>).
func assumedRoleARN(account, session string) string {
	return "arn:aws:sts::" + account + ":assumed-role/" + organizationRole + "/" + session
}

// assume calls AssumeRole as the root user into account's
// OrganizationAccountAccessRole.
func assume(
	t *testing.T,
	srv *server,
	account, session string,
	duration *int32,
) *sts.AssumeRoleOutput {
	t.Helper()
	out, err := stsFor(srv, rootCreds()).AssumeRole(t.Context(), &sts.AssumeRoleInput{
		RoleArn:         aws.String(roleARN(account)),
		RoleSessionName: aws.String(session),
		DurationSeconds: duration,
	})
	requireNoErr(t, err, "assume role in "+account)
	if out.Credentials == nil || out.AssumedRoleUser == nil {
		t.Fatalf("assume role in %s returned no credentials or no AssumedRoleUser", account)
	}
	return out
}

// sessionCreds are the temporary credentials of an AssumeRole answer.
func sessionCreds(out *sts.AssumeRoleOutput) aws.Credentials {
	return aws.Credentials{
		AccessKeyID:     aws.ToString(out.Credentials.AccessKeyId),
		SecretAccessKey: aws.ToString(out.Credentials.SecretAccessKey),
		SessionToken:    aws.ToString(out.Credentials.SessionToken),
	}
}

func TestAssumeRoleIntoMemberAccount(t *testing.T) {
	f := newOrgFixture(t)

	t.Run("credentials", func(t *testing.T) { testAssumeRoleCredentials(t, f) })
	t.Run("session token", func(t *testing.T) { testSessionToken(t, f) })
	t.Run("acts in the member account", func(t *testing.T) { testSessionActsInAccount(t, f) })
	t.Run("DurationSeconds", func(t *testing.T) { testDurationSeconds(t, f) })
	t.Run("RoleSessionName", func(t *testing.T) { testRoleSessionName(t, f) })
	t.Run("refused roles", func(t *testing.T) { testRefusedRoles(t, f) })
	t.Run("refused callers", func(t *testing.T) { testRefusedCallers(t, f) })
	t.Run("key source", func(t *testing.T) { testKeySourceSession(t, f) })
	t.Run("GetUser with no user name", func(t *testing.T) { testSessionGetUser(t, f) })
}

func testAssumeRoleCredentials(t *testing.T, f orgFixture) {
	before := time.Now()
	out := assume(t, f.srv, f.member, "e2e-session", nil)
	after := time.Now()

	c := out.Credentials
	requireMatch(t, tempKeyPattern, aws.ToString(c.AccessKeyId), "AccessKeyId")
	if aws.ToString(c.SecretAccessKey) == "" || aws.ToString(c.SessionToken) == "" {
		t.Fatal("credentials lack a secret or a session token")
	}
	// DurationSeconds: "By default, the value is set to 3600 seconds."
	requireRecent(t, c.Expiration, before.Add(time.Hour), after.Add(time.Hour), "Expiration")

	u := out.AssumedRoleUser
	requireEqual(t, aws.ToString(u.Arn), assumedRoleARN(f.member, "e2e-session"), "Arn")
	// AssumedRoleId contains the role ID and the session name: the aws:userid
	// of a role session is role-id:session-name (policy variables, principal
	// table), and a role ID starts AROA (IAM identifiers).
	roleID, session, ok := strings.Cut(aws.ToString(u.AssumedRoleId), ":")
	if !ok {
		t.Fatalf("AssumedRoleId %q is not role-id:session", aws.ToString(u.AssumedRoleId))
	}
	requireMatch(t, roleIDPattern, roleID, "role ID")
	requireEqual(t, session, "e2e-session", "AssumedRoleId session")

	// The temporary credentials, with their token, sign GetCallerIdentity,
	// which reports the session.
	id, err := callerIdentity(t, f.srv, sessionCreds(out))
	requireNoErr(t, err, "get caller identity with the session")
	requireEqual(t, aws.ToString(id.Arn), aws.ToString(u.Arn), "caller Arn")
	requireEqual(t, aws.ToString(id.UserId), aws.ToString(u.AssumedRoleId), "caller UserId")
	requireEqual(t, aws.ToString(id.Account), f.member, "caller Account")

	// GetAccessKeyInfo of an ASIA key is the account whose role it is.
	info, err := stsFor(f.srv, rootCreds()).GetAccessKeyInfo(t.Context(),
		&sts.GetAccessKeyInfoInput{AccessKeyId: c.AccessKeyId})
	requireNoErr(t, err, "get access key info of the session key")
	requireEqual(t, aws.ToString(info.Account), f.member, "session key Account")

	// A second session of the same role gets its own key; the role ID is the
	// role's, so it is the same.
	again := assume(t, f.srv, f.member, "second", nil)
	if aws.ToString(again.Credentials.AccessKeyId) == aws.ToString(c.AccessKeyId) {
		t.Fatal("two sessions share an access key ID")
	}
	otherRoleID, _, _ := strings.Cut(aws.ToString(again.AssumedRoleUser.AssumedRoleId), ":")
	requireEqual(t, otherRoleID, roleID, "role ID of the second session")
}

func testSessionToken(t *testing.T, f orgFixture) {
	first := sessionCreds(assume(t, f.srv, f.member, "token-one", nil))
	second := sessionCreds(assume(t, f.srv, f.member, "token-two", nil))

	// Each is refused as a token that is not the key's: InvalidClientTokenId,
	// "The security token included in the request is invalid".
	tests := map[string]aws.Credentials{
		"tampered token":          withToken(first, tamper(first.SessionToken)),
		"another session's token": withToken(first, second.SessionToken),
		// sigv4: a temporary key sent without its token is an unknown key,
		// as AWS reports it.
		"no token": withToken(first, ""),
	}
	for name, creds := range tests {
		t.Run(name, func(t *testing.T) {
			requireCode(t, errOf(callerIdentity(t, f.srv, creds)), codeInvalidClientToken)
		})
	}

	t.Run("untampered still works", func(t *testing.T) {
		_, err := callerIdentity(t, f.srv, first)
		requireNoErr(t, err, "get caller identity")
	})
}

func withToken(c aws.Credentials, token string) aws.Credentials {
	c.SessionToken = token
	return c
}

// tamper changes one character in the middle of a token.
func tamper(token string) string {
	b := []byte(token)
	i := len(b) / 2
	if b[i] == 'A' {
		b[i] = 'B'
	} else {
		b[i] = 'A'
	}
	return string(b)
}

func testSessionActsInAccount(t *testing.T, f orgFixture) {
	// The spec: an OrganizationAccountAccessRole session is an admin in its
	// role's account, and acts there.
	sess := sessionCreds(assume(t, f.srv, f.member, "admin", nil))
	mc := iamFor(f.srv, sess)
	root := iamFor(f.srv, rootCreds())

	created, err := mc.CreateUser(t.Context(), &iam.CreateUserInput{
		UserName: aws.String("member-user"),
	})
	requireNoErr(t, err, "create user in the member account")
	requireUser(t, created.User, f.member, "/", "member-user")

	got, err := mc.ListUsers(t.Context(), &iam.ListUsersInput{})
	requireNoErr(t, err, "list users in the member account")
	requireSameNames(t, userNames(got.Users), []string{"member-user"})

	// The management account does not see it.
	requireAs[*iamtypes.NoSuchEntityException](t, errOf(root.GetUser(t.Context(),
		&iam.GetUserInput{UserName: aws.String("member-user")})))

	// Names are unique within an account (CreateUserInput.UserName), so the
	// management account may have a user of the same name.
	mgmt := userWithKey(t, root, "member-user")
	requireAs[*iamtypes.EntityAlreadyExistsException](t, errOf(mc.CreateUser(t.Context(),
		&iam.CreateUserInput{UserName: aws.String("member-user")})))

	// A key of the member's user is in the member account.
	key := createKey(t, mc, "member-user")
	id, err := callerIdentity(t, f.srv, key)
	requireNoErr(t, err, "get caller identity as the member's user")
	requireEqual(t, aws.ToString(id.Account), f.member, "Account")
	requireEqual(t, aws.ToString(id.Arn), userARN(f.member, "/", "member-user"), "Arn")

	mid, err := callerIdentity(t, f.srv, mgmt)
	requireNoErr(t, err, "get caller identity as the management account's user")
	requireEqual(t, aws.ToString(mid.Account), defaultAccountID, "management user's Account")

	// The session cannot reach the management account's keys.
	requireAs[*iamtypes.NoSuchEntityException](t, errOf(mc.DeleteAccessKey(t.Context(),
		&iam.DeleteAccessKeyInput{
			UserName:    aws.String("member-user"),
			AccessKeyId: aws.String(mgmt.AccessKeyID),
		})))

	// A user of the member account is not an admin.
	requireCode(t, errOf(iamFor(f.srv, key).ListUsers(t.Context(), &iam.ListUsersInput{})),
		codeAccessDenied)
}

func testDurationSeconds(t *testing.T, f orgFixture) {
	sc := stsFor(f.srv, rootCreds())

	// DurationSeconds ranges from 900 up to the role's maximum session
	// duration.
	for _, d := range []int32{900, 3600} {
		t.Run(strconv.Itoa(int(d)), func(t *testing.T) {
			before := time.Now()
			out := assume(t, f.srv, f.member, "dur", aws.Int32(d))
			span := time.Duration(d) * time.Second
			requireRecent(t, out.Credentials.Expiration, before.Add(span), time.Now().Add(span),
				"Expiration")
		})
	}

	// roleDurationSecondsType: 900 to 43200, else ValidationError. 3601:
	// above the role's maximum session duration, the operation fails.
	// Assumption: the role's maximum is the one-hour default of CreateRole's
	// MaxSessionDuration, since Organizations creates it without one, and
	// AWS reports exceeding it as ValidationError.
	for _, d := range []int32{0, 899, 3601, 43201} {
		t.Run(strconv.Itoa(int(d)), func(t *testing.T) {
			err := errOf(sc.AssumeRole(t.Context(), &sts.AssumeRoleInput{
				RoleArn:         aws.String(roleARN(f.member)),
				RoleSessionName: aws.String("dur"),
				DurationSeconds: aws.Int32(d),
			}))
			requireCode(t, err, codeValidation)
		})
	}
}

func testRoleSessionName(t *testing.T, f orgFixture) {
	// roleSessionNameType: 2 to 64 characters of [\w+=,.@-].
	sc := stsFor(f.srv, rootCreds())
	for _, name := range []string{"x", "has space", "a/b", strings.Repeat("s", 65)} {
		t.Run(name, func(t *testing.T) {
			err := errOf(sc.AssumeRole(t.Context(), &sts.AssumeRoleInput{
				RoleArn:         aws.String(roleARN(f.member)),
				RoleSessionName: aws.String(name),
			}))
			requireCode(t, err, codeValidation)
		})
	}

	t.Run("longest and every allowed character", func(t *testing.T) {
		for _, name := range []string{strings.Repeat("s", 64), "a_B+c=d,e.f@g-h"} {
			out := assume(t, f.srv, f.member, name, nil)
			requireEqual(t, aws.ToString(out.AssumedRoleUser.Arn),
				assumedRoleARN(f.member, name), "Arn")
		}
	})
}

func testRefusedRoles(t *testing.T, f orgFixture) {
	// None of these roles exists (identity creates OrganizationAccountAccessRole
	// only in an ACTIVE member account), and a role that does not exist
	// answers AccessDenied (see TestAssumeRoleWithoutAccounts). Role names
	// are case sensitive when assumed (IAM User Guide, "Troubleshoot IAM
	// roles"). Assumption: a closed account's role is refused the same way.
	sc := stsFor(f.srv, rootCreds())
	tests := map[string]string{
		"unknown account": roleARN("999999999999"),
		"closed account":  roleARN(f.closed),
		"another role":    "arn:aws:iam::" + f.member + ":role/Admin",
		"other case":      "arn:aws:iam::" + f.member + ":role/organizationaccountaccessrole",
	}
	for name, arn := range tests {
		t.Run(name, func(t *testing.T) {
			err := errOf(sc.AssumeRole(t.Context(), &sts.AssumeRoleInput{
				RoleArn:         aws.String(arn),
				RoleSessionName: aws.String("refused"),
			}))
			requireCode(t, err, codeAccessDenied)
		})
	}
}

func testRefusedCallers(t *testing.T, f orgFixture) {
	// The role trusts the management account, so a management user needs a
	// policy allowing sts:AssumeRole on it, which this one lacks; the
	// session is of the member account, which the role does not trust.
	// Both are denied, in AWS's AccessDenied shape.
	root := iamFor(f.srv, rootCreds())
	userKey := userWithKey(t, root, "would-be-admin")
	sess := sessionCreds(assume(t, f.srv, f.member, "chain", nil))

	for name, creds := range map[string]aws.Credentials{
		"user key":     userKey,
		"role session": sess,
	} {
		t.Run(name, func(t *testing.T) {
			err := errOf(stsFor(f.srv, creds).AssumeRole(t.Context(), &sts.AssumeRoleInput{
				RoleArn:         aws.String(roleARN(f.member)),
				RoleSessionName: aws.String("refused"),
			}))
			requireCode(t, err, codeAccessDenied)
		})
	}
}
