//go:build e2e

package e2e

import (
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/iam/types"
	"tule.dev/policy"
	"tule.dev/sigv4"
)

// principalContext is the aws:PrincipalArn a service supplies for a
// verified principal, as the keysource contract asks: the PrincipalARN when
// there is one, and for a role session without one, a session whose role
// no longer exists, an empty slice, so that the evaluator treats the key as
// absent and derives nothing from the assumed-role ARN.
func principalContext(p sigv4.Principal) map[string][]string {
	switch {
	case p.PrincipalARN != "":
		return map[string][]string{"aws:PrincipalArn": {p.PrincipalARN}}
	case p.Type == sigv4.PrincipalTypeAssumedRole:
		return map[string][]string{"aws:PrincipalArn": {}}
	}
	return nil
}

// allowsRole evaluates a policy that allows s3:GetObject only to sessions of
// the role, by aws:PrincipalArn, for a request by principal with ctx.
func allowsRole(t *testing.T, role, principal string, ctx map[string][]string) bool {
	t.Helper()
	doc, err := policy.ParseIdentity([]byte(`{"Version":"2012-10-17","Statement":[` +
		`{"Effect":"Allow","Action":"s3:GetObject","Resource":"*",` +
		`"Condition":{"ArnEquals":{"aws:PrincipalArn":"` + role + `"}}}]}`))
	requireNoErr(t, err, "parse the policy")
	res := policy.Evaluate(policy.Request{
		Action: "s3:GetObject", Resource: "arn:aws:s3:::bucket/key",
		Principal: principal, Context: ctx,
	}, doc)
	return res.Decision == policy.Allow
}

// A session of a role deleted and created again under its name is not a
// session of the new role: it has no PrincipalArn and no tags, while a
// session of the new role has both. A service that supplies aws:PrincipalArn
// as the contract asks grants the old session nothing the new role's ARN is
// granted; one that leaves the key out lets the evaluator derive the role's
// ARN from the assumed-role ARN, which the old session still carries.
func TestKeySourceOrphanedSessionAttributes(t *testing.T) {
	srv, c := rootIAM(t)
	// At the default path, the role's ARN is the one the evaluator would
	// derive from a session's assumed-role ARN, which names no path.
	role := iamRoleARN(defaultAccountID, "/", "Deployer")
	createTagged := func(value string) string {
		t.Helper()
		out, err := c.CreateRole(t.Context(), &iam.CreateRoleInput{
			RoleName:                 aws.String("Deployer"),
			AssumeRolePolicyDocument: aws.String(trustDoc(rootARN(defaultAccountID))),
			Tags:                     []types.Tag{tag("Project", value)},
		})
		requireNoErr(t, err, "create role")
		return aws.ToString(out.Role.RoleId)
	}
	oldID := createTagged("old")
	key := userWithPolicy(t, c, "dev", canAssume(role))
	old := sessionCreds(mustAssume(t, srv, key, role, "release-1"))

	_, err := c.DeleteRole(t.Context(), &iam.DeleteRoleInput{RoleName: aws.String("Deployer")})
	requireNoErr(t, err, "delete role")
	newID := createTagged("new")
	if newID == oldID {
		t.Fatalf("the role created again has the old role's ID %s", oldID)
	}
	current := sessionCreds(mustAssume(t, srv, key, role, "release-2"))

	p := verifiedPrincipal(t, srv, old)
	requireEqual(t, p.ARN, sessionARN(defaultAccountID, "Deployer", "release-1"), "old ARN")
	requireEqual(t, p.PrincipalARN, "", "old PrincipalARN")
	requireEqual(t, p.UserID, oldID+":release-1", "old UserID")
	requireEqual(t, p.Type, sigv4.PrincipalTypeAssumedRole, "old Type")
	requirePrincipalTags(t, p, nil)
	requirePolicies(t, p)

	n := verifiedPrincipal(t, srv, current)
	requireEqual(t, n.PrincipalARN, role, "new PrincipalARN")
	requireEqual(t, n.UserID, newID+":release-2", "new UserID")
	requirePrincipalTags(t, n, map[string]string{"Project": "new"})

	// The policy evaluator treats the empty aws:PrincipalArn as absent, and
	// derives nothing in its place: the old session is not granted.
	requireEqual(t, allowsRole(t, role, n.ARN, principalContext(n)), true, "new session allowed")
	requireEqual(t, allowsRole(t, role, p.ARN, principalContext(p)), false, "old session allowed")
	// Left out, the key would be derived from the assumed-role ARN, which
	// still names the role, and the old session granted: what the empty
	// slice is for.
	requireEqual(t, allowsRole(t, role, p.ARN, nil), true,
		"old session allowed by a derived aws:PrincipalArn")
}
