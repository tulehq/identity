//go:build e2e

package e2e

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
)

func TestOrganizationRolesWithPolicies(t *testing.T) {
	f := newOrgFixture(t)

	t.Run("OrganizationAccountAccessRole as provisioned", func(t *testing.T) {
		testOrgRoleProvisioned(t, f)
	})
	t.Run("management user with sts:AssumeRole", func(t *testing.T) {
		testManagementUserAssumesOrgRole(t, f)
	})
	t.Run("member role trusting a management user", func(t *testing.T) {
		testCrossAccountRole(t, f)
	})
}

// testOrgRoleProvisioned checks the design: identity creates
// OrganizationAccountAccessRole in the member account "with
// AdministratorAccess attached and a trust policy for the management
// account". Its session sees it as a role of the member account.
func testOrgRoleProvisioned(t *testing.T, f orgFixture) {
	sess := sessionCreds(assume(t, f.srv, f.member, "inspect", nil))
	mc := iamFor(f.srv, sess)

	out, err := mc.GetRole(t.Context(), &iam.GetRoleInput{
		RoleName: aws.String(organizationRole),
	})
	requireNoErr(t, err, "get OrganizationAccountAccessRole in the member account")
	requireEqual(t, aws.ToString(out.Role.Arn), roleARN(f.member), "Arn")

	// The trust policy names the management account, as an account ID or
	// its root ARN; which form is not specified.
	trust, err := json.Marshal(decodeDoc(t, out.Role.AssumeRolePolicyDocument, "trust policy"))
	requireNoErr(t, err, "re-encode the trust policy")
	if !strings.Contains(string(trust), defaultAccountID) {
		t.Fatalf("trust policy %s does not name the management account", trust)
	}

	attached := attachedARNs(attachedRolePolicies(t, mc, organizationRole))
	requireEqual(t, attached["AdministratorAccess"], adminAccessARN, "AdministratorAccess")
}

// testManagementUserAssumesOrgRole: the role's trust policy trusts the
// management account, so a management user whose policy allows
// sts:AssumeRole on the role may assume it (AssumeRole: "your AWS account
// must be trusted by the role" and "The administrator must attach a policy
// that allows the user to call AssumeRole for the ARN of the role in the
// other account"). Without the policy it is denied (testRefusedCallers).
func testManagementUserAssumesOrgRole(t *testing.T, f orgFixture) {
	root := iamFor(f.srv, rootCreds())
	key := userWithPolicy(t, root, "operator", canAssume(roleARN(f.member)))

	out := mustAssume(t, f.srv, key, roleARN(f.member), "operator")
	requireEqual(t, aws.ToString(out.AssumedRoleUser.Arn),
		assumedRoleARN(f.member, "operator"), "Arn")

	// The session has AdministratorAccess in the member account.
	mc := iamFor(f.srv, sessionCreds(out))
	createUser(t, mc, "made-by-operator")

	t.Run("policy on another account's role only", func(t *testing.T) {
		k := userWithPolicy(t, root, "narrow",
			canAssume(roleARN("999999999999")))
		_, err := assumeAs(t, f.srv, k, roleARN(f.member), "narrow", nil)
		requireAssumeDenied(t, err, devARN("narrow"))
	})
}

// testCrossAccountRole: a role the member account creates, trusting one
// management user's ARN, is assumable by that user with an identity policy
// allowing it, and its session has the role's policies in the member
// account. Another management user, though allowed by its own policy, is
// not trusted.
func testCrossAccountRole(t *testing.T, f orgFixture) {
	root := iamFor(f.srv, rootCreds())
	mc := iamFor(f.srv, sessionCreds(assume(t, f.srv, f.member, "setup", nil)))
	cross := iamRoleARN(f.member, "/", "Cross")

	createUser(t, root, "partner")
	createRole(t, mc, "Cross", trustDoc(devARN("partner")))
	putRolePolicy(t, mc, "Cross", "list", policyDoc(allow("iam:ListUsers", "*")))
	putUserPolicy(t, root, "partner", "assume", canAssume(cross))
	key := createKey(t, root, "partner")

	out := mustAssume(t, f.srv, key, cross, "partner")
	requireEqual(t, aws.ToString(out.AssumedRoleUser.Arn),
		sessionARN(f.member, "Cross", "partner"), "Arn")
	id, err := callerIdentity(t, f.srv, sessionCreds(out))
	requireNoErr(t, err, "get caller identity with the session")
	requireEqual(t, aws.ToString(id.Account), f.member, "Account")

	pc := iamFor(f.srv, sessionCreds(out))
	_, err = pc.ListUsers(t.Context(), &iam.ListUsersInput{})
	requireNoErr(t, err, "list the member account's users with the session")
	err = errOf(pc.CreateUser(t.Context(), &iam.CreateUserInput{UserName: aws.String("x")}))
	requireCode(t, err, codeAccessDenied)

	t.Run("untrusted management user", func(t *testing.T) {
		k := userWithPolicy(t, root, "stranger", canAssume(cross))
		_, err := assumeAs(t, f.srv, k, cross, "stranger", nil)
		requireAssumeDenied(t, err, devARN("stranger"))
	})
}
