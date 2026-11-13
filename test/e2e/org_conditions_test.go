//go:build e2e

package e2e

import (
	"strconv"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
)

// conditioned is a statement with effect on action and "*", under one
// condition operator on key.
func conditioned(effect, action, operator, key, value string) string {
	return `{"Effect":"` + effect + `","Action":"` + action + `","Resource":"*",` +
		`"Condition":{"` + operator + `":{"` + key + `":"` + value + `"}}}`
}

// statements is an identity policy of the statements.
func statements(stmts ...string) string {
	doc := `{"Version":"2012-10-17","Statement":[`
	for i, s := range stmts {
		if i > 0 {
			doc += ","
		}
		doc += s
	}
	return doc + "]}"
}

// allowed reports whether creds may call ListUsers, ListRoles or
// ListPolicies, by name.
func allowed(t *testing.T, srv *server, creds aws.Credentials, op string) bool {
	t.Helper()
	c := iamFor(srv, creds)
	var err error
	switch op {
	case "ListUsers":
		err = errOf(c.ListUsers(t.Context(), &iam.ListUsersInput{}))
	case "ListRoles":
		err = errOf(c.ListRoles(t.Context(), &iam.ListRolesInput{}))
	case "ListPolicies":
		err = errOf(c.ListPolicies(t.Context(), &iam.ListPoliciesInput{}))
	default:
		t.Fatalf("no operation %s", op)
	}
	if err != nil {
		requireCode(t, err, codeAccessDenied)
		return false
	}
	return true
}

// Identity's own evaluation supplies aws:PrincipalOrgID and
// aws:PrincipalOrgPaths, to identity policies and to trust policies.
func TestIdentityEvaluatesTheOrganizationKeys(t *testing.T) {
	f := newOrgKeysFixture(t)
	root := iamFor(f.srv, rootCreds())
	rootPath := f.orgID + "/" + f.rootID + "/"

	// A management account user, in the organization.
	user := userWithPolicy(t, root, "manager", statements(
		conditioned("Allow", "iam:ListUsers", "StringEquals", "aws:PrincipalOrgID", f.orgID),
		conditioned("Allow", "iam:ListRoles", "ForAnyValue:StringLike",
			"aws:PrincipalOrgPaths", rootPath+"*"),
		conditioned("Allow", "iam:ListPolicies", "StringEquals", "aws:PrincipalOrgID",
			"o-0000000000"),
	))
	for op, want := range map[string]bool{
		"ListUsers": true, "ListRoles": true, "ListPolicies": false,
	} {
		requireEqual(t, allowed(t, f.srv, user, op), want, "manager "+op)
	}

	// A trust policy that trusts the account within the organization.
	createRole(t, root, "org-only", `{"Version":"2012-10-17","Statement":[{"Effect":"Allow",`+
		`"Principal":{"AWS":"`+defaultAccountID+`"},"Action":"sts:AssumeRole",`+
		`"Condition":{"StringEquals":{"aws:PrincipalOrgID":"`+f.orgID+`"}}}]}`)
	mustAssume(t, f.srv, rootCreds(), iamRoleARN(defaultAccountID, "/", "org-only"), "in-org")
}

// A principal of an account removed from the organization has neither key:
// a condition on its organization ID does not hold, and a negated one does.
func TestARemovedAccountIsOutsideTheOrganization(t *testing.T) {
	f := newOrgKeysFixture(t)
	removed := iamFor(f.srv, f.removed)
	requireNoErr(t, errOf(removed.CreateUser(t.Context(), &iam.CreateUserInput{
		UserName: aws.String("left"),
	})), "create a user in the removed account")
	requireNoErr(t, errOf(removed.PutUserPolicy(t.Context(), &iam.PutUserPolicyInput{
		UserName: aws.String("left"), PolicyName: aws.String("org"),
		PolicyDocument: aws.String(statements(
			conditioned("Allow", "iam:ListUsers", "StringEquals", "aws:PrincipalOrgID", f.orgID),
			conditioned("Allow", "iam:ListRoles", "StringNotEquals", "aws:PrincipalOrgID",
				f.orgID),
		)),
	})), "put the user's policy")
	key := createKey(t, removed, "left")
	requireEqual(t, allowed(t, f.srv, key, "ListUsers"), false, "ListUsers in the org")
	requireEqual(t, allowed(t, f.srv, key, "ListRoles"), true, "ListRoles outside the org")
}

// When the accounts service cannot be reached the keys are unknown, and a
// condition on them fails closed: it never helps an Allow, and always lets
// a Deny apply. Requests that do not test them are decided as usual.
func TestUnknownOrganizationKeysFailClosed(t *testing.T) {
	srv := startServer(t, map[string]string{
		"TULE_Identity_AccountsEndpoint": "http://127.0.0.1:" + strconv.Itoa(freePort(t)),
	})
	root := iamFor(srv, rootCreds())
	user := userWithPolicy(t, root, "dev", statements(
		// Absent, the key would let this Allow hold.
		conditioned("Allow", "iam:ListUsers", "StringNotEquals", "aws:PrincipalOrgID",
			"o-0000000000"),
		`{"Effect":"Allow","Action":["iam:ListRoles","iam:ListPolicies"],"Resource":"*"}`,
		// Absent, the key would let this Deny lapse.
		conditioned("Deny", "iam:ListRoles", "StringLike", "aws:PrincipalOrgID", "o-*"),
	))
	for op, want := range map[string]bool{
		"ListUsers": false, "ListRoles": false, "ListPolicies": true,
	} {
		requireEqual(t, allowed(t, srv, user, op), want, "dev "+op)
	}

	createRole(t, root, "org-out", `{"Version":"2012-10-17","Statement":[{"Effect":"Allow",`+
		`"Principal":{"AWS":"`+defaultAccountID+`"},"Action":"sts:AssumeRole",`+
		`"Condition":{"StringNotEquals":{"aws:PrincipalOrgID":"o-0000000000"}}}]}`)
	_, err := assumeAs(t, srv, rootCreds(), iamRoleARN(defaultAccountID, "/", "org-out"),
		"unknown", nil)
	requireAssumeDenied(t, err, "arn:aws:iam::"+defaultAccountID+":root")
}
