//go:build e2e

package e2e

import (
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/aws/smithy-go"
)

func TestRootGetUser(t *testing.T) {
	// GetUser: "If you do not specify a user name, IAM determines the user
	// name implicitly based on the AWS access key ID used to sign the
	// request." Assumption: the reference does not show the root user's
	// answer; its ARN is arn:aws:iam::<account>:root (IAM identifiers) and
	// its unique ID the account ID (aws:userid of the root user, policy
	// variables, principal table), as GetCallerIdentity reports them.
	_, c := rootIAM(t)
	createUser(t, c, "dev")

	out, err := c.GetUser(t.Context(), &iam.GetUserInput{})
	requireNoErr(t, err, "get user with no user name")
	if out.User == nil {
		t.Fatal("no user returned")
	}
	requireEqual(t, aws.ToString(out.User.Arn), "arn:aws:iam::"+defaultAccountID+":root", "Arn")
	requireEqual(t, aws.ToString(out.User.UserId), defaultAccountID, "UserId")
}

func TestRootListAccessKeys(t *testing.T) {
	// ListAccessKeys: with no UserName, the user is the signer's, and "the
	// root user returns it's own access key IDs". A user existing in the
	// account does not change whose keys are listed.
	_, c := rootIAM(t)
	userWithKey(t, c, "dev")

	keys := rootKeys(t, c)
	requireEqual(t, len(keys), 1, "root key count")
	requireEqual(t, aws.ToString(keys[0].AccessKeyId), rootKeyID, "AccessKeyId")
	requireEqual(t, keys[0].Status, types.StatusTypeActive, "Status")
}

func TestRootKeysCannotBeChanged(t *testing.T) {
	// The root key comes from the configuration, so identity refuses to
	// create, update or delete root keys. The code is a documented
	// difference from AWS, so only the refusal and its effect are checked.
	srv, c := rootIAM(t)
	root := aws.String(rootKeyID)

	calls := map[string]func() error{
		"CreateAccessKey": func() error {
			return errOf(c.CreateAccessKey(t.Context(), &iam.CreateAccessKeyInput{}))
		},
		"UpdateAccessKey": func() error {
			return errOf(c.UpdateAccessKey(t.Context(), &iam.UpdateAccessKeyInput{
				AccessKeyId: root, Status: types.StatusTypeInactive,
			}))
		},
		"DeleteAccessKey": func() error {
			return errOf(c.DeleteAccessKey(t.Context(), &iam.DeleteAccessKeyInput{
				AccessKeyId: root,
			}))
		},
	}
	for name, call := range calls {
		t.Run(name, func(t *testing.T) {
			var apiErr smithy.APIError
			if err := call(); !errors.As(err, &apiErr) {
				t.Fatalf("want an API error, got %v", err)
			}

			keys := rootKeys(t, c)
			requireEqual(t, len(keys), 1, "root key count")
			requireEqual(t, aws.ToString(keys[0].AccessKeyId), rootKeyID, "AccessKeyId")
			requireEqual(t, keys[0].Status, types.StatusTypeActive, "Status")
			_, err := callerIdentity(t, srv, rootCreds())
			requireNoErr(t, err, "root key still signs")
		})
	}
}

func rootKeys(t *testing.T, c *iam.Client) []types.AccessKeyMetadata {
	t.Helper()
	out, err := c.ListAccessKeys(t.Context(), &iam.ListAccessKeysInput{})
	requireNoErr(t, err, "list access keys with no user name")
	return out.AccessKeyMetadata
}

// testSessionGetUser checks GetUser with no UserName from a role session:
// a session is not a user, and IAM answers ValidationError "Must specify
// userName when calling with non-User credentials". Assumption: that is the
// message IAM sends; the reference does not quote it.
func testSessionGetUser(t *testing.T, f orgFixture) {
	sess := sessionCreds(assume(t, f.srv, f.member, "who-am-i", nil))
	err := errOf(iamFor(f.srv, sess).GetUser(t.Context(), &iam.GetUserInput{}))
	requireCode(t, err, codeValidation)
	var apiErr smithy.APIError
	if errors.As(err, &apiErr) {
		requireEqual(t, apiErr.ErrorMessage(),
			"Must specify userName when calling with non-User credentials", "message")
	}
}
