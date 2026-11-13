//go:build e2e

package e2e

import (
	"strconv"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsorg "github.com/aws/aws-sdk-go-v2/service/organizations"
	"tule.dev/sigv4"
)

// orgKeysFixture is an identity server over an accounts service whose
// organization has a member account in an OU, a member account under the
// root, and a session of an account since removed from the organization.
// The organization is set up before identity first asks about any account,
// so no organization key is cached before the test looks.
type orgKeysFixture struct {
	srv     *server
	orgID   string
	rootID  string
	ouID    string
	inOU    string
	atRoot  string
	removed aws.Credentials
}

func newOrgKeysFixture(t *testing.T) orgKeysFixture {
	t.Helper()

	url := startAccounts(t)
	oc := orgClient(url)
	org, err := oc.CreateOrganization(t.Context(), &awsorg.CreateOrganizationInput{})
	requireNoErr(t, err, "create organization")
	roots, err := oc.ListRoots(t.Context(), &awsorg.ListRootsInput{})
	requireNoErr(t, err, "list roots")
	f := orgKeysFixture{
		orgID:  aws.ToString(org.Organization.Id),
		rootID: aws.ToString(roots.Roots[0].Id),
		inOU:   createOrgAccount(t, oc, "InOU", "in-ou@example.com"),
		atRoot: createOrgAccount(t, oc, "AtRoot", "at-root@example.com"),
	}
	ou, err := oc.CreateOrganizationalUnit(t.Context(), &awsorg.CreateOrganizationalUnitInput{
		ParentId: aws.String(f.rootID), Name: aws.String("Workloads"),
	})
	requireNoErr(t, err, "create OU")
	f.ouID = aws.ToString(ou.OrganizationalUnit.Id)
	requireNoErr(t, errOf(oc.MoveAccount(t.Context(), &awsorg.MoveAccountInput{
		AccountId: aws.String(f.inOU), SourceParentId: aws.String(f.rootID),
		DestinationParentId: aws.String(f.ouID),
	})), "move the account into the OU")
	removed := createOrgAccount(t, oc, "Removed", "removed@example.com")

	f.srv = startServer(t, map[string]string{"TULE_Identity_AccountsEndpoint": url})
	// A session of the account, taken while it is a member: the account is
	// then removed, before anything asks for its organization keys.
	f.removed = sessionCreds(assume(t, f.srv, removed, "leaving", nil))
	requireNoErr(t, errOf(oc.RemoveAccountFromOrganization(t.Context(),
		&awsorg.RemoveAccountFromOrganizationInput{AccountId: aws.String(removed)})),
		"remove the account from the organization")
	return f
}

// requireOrgKeys fails unless p carries orgID and the one path, or, for an
// empty orgID, neither key, known.
func requireOrgKeys(t *testing.T, p sigv4.Principal, orgID, path string) {
	t.Helper()
	var paths []string
	if path != "" {
		paths = []string{path}
	}
	if p.OrgID != orgID || len(p.OrgPaths) != len(paths) ||
		(len(paths) == 1 && p.OrgPaths[0] != path) || p.OrgUnknown {
		t.Fatalf("organization keys of %s = %q %q unknown %t; want %q %q",
			p.ARN, p.OrgID, p.OrgPaths, p.OrgUnknown, orgID, paths)
	}
}

// AWS includes aws:PrincipalOrgID and aws:PrincipalOrgPaths "only if the
// principal is a member of an organization", the management account
// included, and a path is the organization, root and OU IDs, each followed
// by a slash (the IAM User Guide, AWS global condition context keys).
func TestTheKeySourceReportsTheOrganizationKeys(t *testing.T) {
	f := newOrgKeysFixture(t)
	rootPath := f.orgID + "/" + f.rootID + "/"

	t.Run("a member account in an OU", func(t *testing.T) {
		sess := sessionCreds(assume(t, f.srv, f.inOU, "in-ou", nil))
		requireOrgKeys(t, verifiedPrincipal(t, f.srv, sess), f.orgID, rootPath+f.ouID+"/")
	})
	t.Run("a member account under the root", func(t *testing.T) {
		sess := sessionCreds(assume(t, f.srv, f.atRoot, "at-root", nil))
		requireOrgKeys(t, verifiedPrincipal(t, f.srv, sess), f.orgID, rootPath)
	})
	t.Run("the management account", func(t *testing.T) {
		root := iamFor(f.srv, rootCreds())
		user := userWithKey(t, root, "manager")
		requireOrgKeys(t, verifiedPrincipal(t, f.srv, rootCreds()), f.orgID, rootPath)
		requireOrgKeys(t, verifiedPrincipal(t, f.srv, user), f.orgID, rootPath)
	})
	t.Run("an account removed from the organization", func(t *testing.T) {
		requireOrgKeys(t, verifiedPrincipal(t, f.srv, f.removed), "", "")
	})
}

func TestWithoutAnAccountsServiceThereIsNoOrganization(t *testing.T) {
	srv, _ := rootIAM(t)
	requireOrgKeys(t, verifiedPrincipal(t, srv, rootCreds()), "", "")
}

// When the accounts service cannot be reached, the keys are unknown, not
// absent, and every request still verifies.
func TestUnreachableAccountsLeaveTheOrganizationUnknown(t *testing.T) {
	srv := startServer(t, map[string]string{
		"TULE_Identity_AccountsEndpoint": "http://127.0.0.1:" + strconv.Itoa(freePort(t)),
	})
	user := userWithKey(t, iamFor(srv, rootCreds()), "dev")
	for _, creds := range []aws.Credentials{rootCreds(), user} {
		p := verifiedPrincipal(t, srv, creds)
		if !p.OrgUnknown || p.OrgID != "" || p.OrgPaths != nil {
			t.Fatalf("organization keys of %s = %q %q unknown %t; want unknown",
				p.ARN, p.OrgID, p.OrgPaths, p.OrgUnknown)
		}
	}
}
