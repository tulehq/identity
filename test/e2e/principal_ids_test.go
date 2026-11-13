//go:build e2e

package e2e

import (
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/iam/types"
	"tule.dev/policy"
	"tule.dev/sigv4"

	"tule.dev/identity/principals"
)

// principalsFor returns a principal-ID client for srv, signed with creds.
func principalsFor(t *testing.T, srv *server, creds aws.Credentials) *principals.Client {
	t.Helper()
	c, err := principals.New(principals.Config{
		HTTPClient:      srv.Client(),
		Endpoint:        srv.URL,
		AccessKeyID:     creds.AccessKeyID,
		SecretAccessKey: creds.SecretAccessKey,
	})
	requireNoErr(t, err, "new principals client")
	return c
}

// bucketGrant is an S3 bucket policy granting s3:GetObject to the AWS
// principals.
func bucketGrant(principals ...string) string {
	return policyDoc(statement{
		Effect:    "Allow",
		Action:    "s3:GetObject",
		Resource:  "arn:aws:s3:::bucket/*",
		Principal: map[string]any{"AWS": principals},
	})
}

// grantedBy reports whether a service holding the stored resource-based
// policy, and verifying through identity, allows creds s3:GetObject on an
// object of the bucket: the principal the key source reports, as
// tule.dev/policy's Caller, against the stored policy.
func grantedBy(t *testing.T, srv *server, stored string, creds aws.Credentials) bool {
	t.Helper()
	verified, err := verifierFor(t, keySourceFor(t, srv, rootCreds())).
		Verify(signedRequest(t, creds))
	requireNoErr(t, err, "verify the request")
	p, _ := sigv4.PrincipalFrom(verified.Context())
	resource, err := policy.ParseResource([]byte(stored))
	requireNoErr(t, err, "parse the stored policy")
	return policy.Authorize(policy.AuthorizeRequest{
		Action:          "s3:GetObject",
		Resource:        "arn:aws:s3:::bucket/key",
		ResourceAccount: defaultAccountID,
		Caller: policy.Caller{
			AccountID: p.AccountID, ARN: p.ARN, PrincipalARN: p.PrincipalARN,
			UserID: p.UserID, Type: policy.PrincipalType(p.Type),
		},
	}, resource).Decision == policy.Allow
}

// recreate deletes the IAM user, with its access keys, and the role, and
// creates both again under the same names.
func recreate(t *testing.T, root *iam.Client, user string, key aws.Credentials, role string) {
	t.Helper()
	requireNoErr(t, errOf(root.DeleteAccessKey(t.Context(), &iam.DeleteAccessKeyInput{
		UserName: aws.String(user), AccessKeyId: aws.String(key.AccessKeyID),
	})), "delete the access key")
	requireNoErr(t, errOf(root.DeleteUser(t.Context(), &iam.DeleteUserInput{
		UserName: aws.String(user),
	})), "delete the IAM user")
	requireNoErr(t, errOf(root.DeleteRole(t.Context(), &iam.DeleteRoleInput{
		RoleName: aws.String(role),
	})), "delete the role")
	createUser(t, root, user)
	createRole(t, root, role, trustDoc(defaultAccountID))
}

// A user and a role named in a resource-based policy, deleted and created
// again under the same names, are other principals: the bound policy no
// longer grants them, and shows the old unique IDs, until it is saved again
// (the IAM User Guide, AWS JSON policy elements: Principal, IAM role
// principals and IAM user principals).
func TestARecreatedPrincipalDoesNotInheritAResourceGrant(t *testing.T) {
	srv, root := rootIAM(t)
	userKey := userWithKey(t, root, "reader")
	createRole(t, root, "deployer", trustDoc(defaultAccountID))
	userARN := "arn:aws:iam::" + defaultAccountID + ":user/reader"
	roleARN := iamRoleARN(defaultAccountID, "/", "deployer")
	oldUser := aws.ToString(getUserOut(t, root, "reader").UserId)
	oldRole := aws.ToString(getRole(t, root, "deployer").RoleId)
	c := principalsFor(t, srv, rootCreds())

	sent := bucketGrant(userARN, roleARN)
	stored, err := c.Bind(t.Context(), sent)
	requireNoErr(t, err, "bind the bucket policy")
	requireEqual(t, stored, bucketGrant(oldUser, oldRole), "bound policy")
	shown, err := c.Show(t.Context(), stored)
	requireNoErr(t, err, "show the bucket policy")
	requireEqual(t, shown, sent, "shown policy")

	// The grant names the IAM user and a session of the role, by unique ID.
	session := sessionCreds(mustAssume(t, srv, rootCreds(), roleARN, "before"))
	requireEqual(t, grantedBy(t, srv, stored, userKey), true, "the IAM user is granted")
	requireEqual(t, grantedBy(t, srv, stored, session), true, "the role's session is granted")

	recreate(t, root, "reader", userKey, "deployer")
	newKey := createKey(t, root, "reader")
	newSession := sessionCreds(mustAssume(t, srv, rootCreds(), roleARN, "after"))
	// Matched by ARN, as a policy stored unbound is, the recreated user
	// inherits the grant; bound, it does not.
	requireEqual(t, grantedBy(t, srv, sent, newKey), true, "the unbound policy grants the new user")
	requireEqual(t, grantedBy(t, srv, stored, newKey), false, "the recreated user is granted")
	requireEqual(t, grantedBy(t, srv, stored, newSession), false,
		"a session of the recreated role is granted")

	// Shown, the policy names the old IDs, which no principal has now.
	shown, err = c.Show(t.Context(), stored)
	requireNoErr(t, err, "show the stale bucket policy")
	requireEqual(t, shown, bucketGrant(oldUser, oldRole), "shown stale policy")

	// Saved again, it names the new principals, and grants them.
	newUser := aws.ToString(getUserOut(t, root, "reader").UserId)
	newRole := aws.ToString(getRole(t, root, "deployer").RoleId)
	if newUser == oldUser || newRole == oldRole {
		t.Fatal("a recreated principal kept its unique ID")
	}
	rebound, err := c.Bind(t.Context(), sent)
	requireNoErr(t, err, "bind the bucket policy again")
	requireEqual(t, rebound, bucketGrant(newUser, newRole), "rebound policy")
	requireEqual(t, grantedBy(t, srv, rebound, newKey), true, "the new user is granted")
	requireEqual(t, grantedBy(t, srv, rebound, newSession), true,
		"a session of the new role is granted")
}

func TestBindRefusesAPrincipalNoUserOrRoleHas(t *testing.T) {
	srv, _ := rootIAM(t)
	nobody := "arn:aws:iam::" + defaultAccountID + ":user/nobody"
	_, err := principalsFor(t, srv, rootCreds()).Bind(t.Context(), bucketGrant(nobody))
	var invalid *principals.InvalidPrincipalError
	if !errors.As(err, &invalid) || invalid.ARN != nobody {
		t.Fatalf("bind naming %s: %v; want an invalid principal", nobody, err)
	}
}

func getUserOut(t *testing.T, c *iam.Client, name string) *types.User {
	t.Helper()
	out, err := c.GetUser(t.Context(), &iam.GetUserInput{UserName: aws.String(name)})
	requireNoErr(t, err, "get user "+name)
	return out.User
}
