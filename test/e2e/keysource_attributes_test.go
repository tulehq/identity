//go:build e2e

package e2e

import (
	"maps"
	"regexp"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/iam/types"
	"tule.dev/sigv4"
)

// requirePrincipalTags fails unless the principal carries exactly want as
// its aws:PrincipalTag values, keys in the case they were set with.
func requirePrincipalTags(t *testing.T, p sigv4.Principal, want map[string]string) {
	t.Helper()
	if !maps.Equal(p.Tags, want) {
		t.Fatalf("principal tags = %v, want %v", p.Tags, want)
	}
}

func TestKeySourceRootAttributes(t *testing.T) {
	// The IAM User Guide, principal key values: the root user's aws:userid
	// is the account ID and its aws:PrincipalType Account; its
	// aws:PrincipalArn is arn:aws:iam::<account>:root (global condition
	// context keys).
	srv := startServer(t, nil)
	p := verifiedPrincipal(t, srv, rootCreds())
	requireEqual(t, p.PrincipalARN, rootARN(defaultAccountID), "PrincipalARN")
	requireEqual(t, p.UserID, defaultAccountID, "UserID")
	requireEqual(t, p.Type, sigv4.PrincipalTypeAccount, "Type")
	requirePrincipalTags(t, p, nil)
}

func TestKeySourceUserAttributes(t *testing.T) {
	// A user's aws:PrincipalArn is its ARN, with its path; its aws:userid
	// its unique ID; its aws:PrincipalType User; and its aws:PrincipalTag
	// values its tags.
	srv, c := rootIAM(t)
	out, err := c.CreateUser(t.Context(), &iam.CreateUserInput{
		UserName: aws.String("builder"), Path: aws.String("/eng/ci/"),
		Tags: []types.Tag{tag("Team", "blue"), tag("env", "dev")},
	})
	requireNoErr(t, err, "create user")
	key := createKey(t, c, "builder")

	p := verifiedPrincipal(t, srv, key)
	arn := "arn:aws:iam::" + defaultAccountID + ":user/eng/ci/builder"
	requireEqual(t, p.ARN, arn, "ARN")
	requireEqual(t, p.PrincipalARN, arn, "PrincipalARN")
	requireEqual(t, p.UserID, aws.ToString(out.User.UserId), "UserID")
	requireMatch(t, userIDPattern, p.UserID, "UserID")
	requireEqual(t, p.Type, sigv4.PrincipalTypeUser, "Type")
	requirePrincipalTags(t, p, map[string]string{"Team": "blue", "env": "dev"})

	t.Run("follows tag changes", func(t *testing.T) {
		// A user's tag keys are not case sensitive (IAM User Guide, tagging
		// IAM resources): team replaces Team, key and value.
		tagUser(t, c, "builder", tag("team", "red"))
		requirePrincipalTags(t, verifiedPrincipal(t, srv, key),
			map[string]string{"team": "red", "env": "dev"})
	})

	t.Run("at the tag limit", func(t *testing.T) {
		tags := make([]types.Tag, 0, maxTags)
		want := map[string]string{}
		for i := range maxTags {
			k, v := "k"+string(rune('A'+i%26))+string(rune('a'+i/26)), "v"
			tags = append(tags, tag(k, v))
			want[k] = v
		}
		_, err := c.CreateUser(t.Context(), &iam.CreateUserInput{
			UserName: aws.String("tagged"), Tags: tags,
		})
		requireNoErr(t, err, "create a user with 50 tags")
		requirePrincipalTags(t, verifiedPrincipal(t, srv, createKey(t, c, "tagged")), want)
	})
}

func TestKeySourceSessionAttributes(t *testing.T) {
	// A role session's aws:PrincipalArn is its role's ARN, path included,
	// which its assumed-role ARN leaves out (IAM identifiers); its
	// aws:userid <role id>:<session name>; its aws:PrincipalType
	// AssumedRole (principal key values); and its aws:PrincipalTag values
	// its role's tags.
	srv, c := rootIAM(t)
	role := iamRoleARN(defaultAccountID, "/app/prod/", "Deployer")
	created, err := c.CreateRole(t.Context(), &iam.CreateRoleInput{
		RoleName: aws.String("Deployer"), Path: aws.String("/app/prod/"),
		AssumeRolePolicyDocument: aws.String(trustDoc(rootARN(defaultAccountID))),
		Tags:                     []types.Tag{tag("Project", "pegasus")},
	})
	requireNoErr(t, err, "create role")
	key := userWithPolicy(t, c, "dev", canAssume(role))

	out := mustAssume(t, srv, key, role, "release-42")
	p := verifiedPrincipal(t, srv, sessionCreds(out))
	requireEqual(t, p.ARN, sessionARN(defaultAccountID, "Deployer", "release-42"), "ARN")
	requireEqual(t, p.PrincipalARN, role, "PrincipalARN")
	requireEqual(t, p.UserID, aws.ToString(created.Role.RoleId)+":release-42", "UserID")
	requireEqual(t, p.UserID, aws.ToString(out.AssumedRoleUser.AssumedRoleId), "UserID")
	requireEqual(t, p.Type, sigv4.PrincipalTypeAssumedRole, "Type")
	requirePrincipalTags(t, p, map[string]string{"Project": "pegasus"})
}

func TestKeySourceServiceRoleSessionAttributes(t *testing.T) {
	// A session from the assume-role endpoint is a role session: its
	// PrincipalArn is the role's ARN with its path, and its UserId the
	// role's ID and the session's name.
	srv, root := rootIAM(t)
	role := iamRoleARN(defaultAccountID, "/service-role/", "fn-exec")
	created, err := root.CreateRole(t.Context(), &iam.CreateRoleInput{
		RoleName: aws.String("fn-exec"), Path: aws.String("/service-role/"),
		AssumeRolePolicyDocument: aws.String(`{"Version":"2012-10-17","Statement":[` +
			`{"Effect":"Allow","Principal":{"Service":"lambda.amazonaws.com"},` +
			`"Action":"sts:AssumeRole"}]}`),
		Tags: []types.Tag{tag("function", "resize")},
	})
	requireNoErr(t, err, "create role")
	s, err := serviceRoleClient(t, srv, rootCreds()).AssumeServiceRole(t.Context(), role,
		"invocation", "lambda.amazonaws.com", 15*time.Minute)
	requireNoErr(t, err, "assume the execution role")

	p := verifiedPrincipal(t, srv, aws.Credentials{
		AccessKeyID:     s.Credentials.AccessKeyID,
		SecretAccessKey: s.Credentials.SecretAccessKey,
		SessionToken:    s.Credentials.SessionToken,
	})
	requireEqual(t, p.ARN, sessionARN(defaultAccountID, "fn-exec", "invocation"), "ARN")
	requireEqual(t, p.PrincipalARN, role, "PrincipalARN")
	requireEqual(t, p.UserID, aws.ToString(created.Role.RoleId)+":invocation", "UserID")
	requireEqual(t, p.UserID, s.AssumedRoleUser.AssumedRoleID, "UserID")
	requireEqual(t, p.Type, sigv4.PrincipalTypeAssumedRole, "Type")
	requirePrincipalTags(t, p, map[string]string{"function": "resize"})
}

// sessionUserIDPattern is a role session's aws:userid: the role's unique ID
// and the session's name.
func sessionUserIDPattern(session string) *regexp.Regexp {
	return regexp.MustCompile(`^AROA[A-Z0-9]+:` + regexp.QuoteMeta(session) + `$`)
}
