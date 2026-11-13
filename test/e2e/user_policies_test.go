//go:build e2e

package e2e

import (
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/iam/types"
)

func attachUserPolicy(t *testing.T, c *iam.Client, user, arn string) {
	t.Helper()
	_, err := c.AttachUserPolicy(t.Context(), &iam.AttachUserPolicyInput{
		UserName: aws.String(user), PolicyArn: aws.String(arn),
	})
	requireNoErr(t, err, "attach "+arn+" to "+user)
}

func detachUserPolicy(t *testing.T, c *iam.Client, user, arn string) {
	t.Helper()
	_, err := c.DetachUserPolicy(t.Context(), &iam.DetachUserPolicyInput{
		UserName: aws.String(user), PolicyArn: aws.String(arn),
	})
	requireNoErr(t, err, "detach "+arn+" from "+user)
}

func putUserPolicy(t *testing.T, c *iam.Client, user, name, doc string) {
	t.Helper()
	_, err := c.PutUserPolicy(t.Context(), &iam.PutUserPolicyInput{
		UserName: aws.String(user), PolicyName: aws.String(name), PolicyDocument: aws.String(doc),
	})
	requireNoErr(t, err, "put user policy "+name+" on "+user)
}

// userWithPolicy creates a user with an inline policy holding doc and an
// access key, and returns the key.
func userWithPolicy(t *testing.T, c *iam.Client, name, doc string) aws.Credentials {
	t.Helper()
	createUser(t, c, name)
	putUserPolicy(t, c, name, "inline", doc)
	return createKey(t, c, name)
}

func attachedUserPolicies(t *testing.T, c *iam.Client, user string) []types.AttachedPolicy {
	t.Helper()
	out, err := c.ListAttachedUserPolicies(t.Context(), &iam.ListAttachedUserPoliciesInput{
		UserName: aws.String(user),
	})
	requireNoErr(t, err, "list attached user policies of "+user)
	return out.AttachedPolicies
}

func userPolicyNames(t *testing.T, c *iam.Client, user string) []string {
	t.Helper()
	out, err := c.ListUserPolicies(t.Context(), &iam.ListUserPoliciesInput{
		UserName: aws.String(user),
	})
	requireNoErr(t, err, "list user policies of "+user)
	return out.PolicyNames
}

// attachedARNs maps each attached policy's name to its ARN.
func attachedARNs(attached []types.AttachedPolicy) map[string]string {
	m := make(map[string]string, len(attached))
	for _, a := range attached {
		m[aws.ToString(a.PolicyName)] = aws.ToString(a.PolicyArn)
	}
	return m
}

func TestAttachUserPolicy(t *testing.T) {
	_, c := rootIAM(t)
	createUser(t, c, "dev")
	mine := createPolicy(t, c, "Mine", policyDoc(allow("iam:GetUser", "*")))

	// ListAttachedUserPolicies: "If there are no managed policies attached
	// to the specified user, the operation returns an empty list."
	requireEqual(t, len(attachedUserPolicies(t, c, "dev")), 0, "attached before")

	attachUserPolicy(t, c, "dev", mine)
	attachUserPolicy(t, c, "dev", adminAccessARN)
	got := attachedARNs(attachedUserPolicies(t, c, "dev"))
	want := map[string]string{"Mine": mine, "AdministratorAccess": adminAccessARN}
	if len(got) != len(want) || got["Mine"] != mine ||
		got["AdministratorAccess"] != adminAccessARN {
		t.Fatalf("attached policies: got %v, want %v", got, want)
	}
	requireEqual(t, aws.ToInt32(getPolicy(t, c, mine).AttachmentCount), 1, "AttachmentCount")

	// Attached managed policies are not inline policies.
	requireEqual(t, len(userPolicyNames(t, c, "dev")), 0, "inline policies")

	detachUserPolicy(t, c, "dev", mine)
	got = attachedARNs(attachedUserPolicies(t, c, "dev"))
	if len(got) != 1 || got["AdministratorAccess"] != adminAccessARN {
		t.Fatalf("attached after detaching Mine: %v", got)
	}
	requireEqual(t, aws.ToInt32(getPolicy(t, c, mine).AttachmentCount), 0, "AttachmentCount")

	// Assumption: detaching a policy that is not attached is NoSuchEntity,
	// which DetachUserPolicy lists; the reference does not name the case.
	t.Run("detach a policy that is not attached", func(t *testing.T) {
		err := errOf(c.DetachUserPolicy(t.Context(), &iam.DetachUserPolicyInput{
			UserName: aws.String("dev"), PolicyArn: aws.String(mine),
		}))
		requireAs[*types.NoSuchEntityException](t, err)
	})

	t.Run("unknown user", func(t *testing.T) {
		requireAs[*types.NoSuchEntityException](t, errOf(c.AttachUserPolicy(t.Context(),
			&iam.AttachUserPolicyInput{
				UserName: aws.String("nobody"), PolicyArn: aws.String(mine),
			})))
		requireAs[*types.NoSuchEntityException](t, errOf(c.ListAttachedUserPolicies(t.Context(),
			&iam.ListAttachedUserPoliciesInput{UserName: aws.String("nobody")})))
	})
}

func TestUserInlinePolicy(t *testing.T) {
	_, c := rootIAM(t)
	createUser(t, c, "dev")
	first := policyDoc(allow("iam:GetUser", "*"))
	second := policyDoc(allow("iam:ListUsers", "*"))

	putUserPolicy(t, c, "dev", "Reader", first)
	putUserPolicy(t, c, "dev", "Other", second)
	requireSameNames(t, userPolicyNames(t, c, "dev"), []string{"Reader", "Other"})

	out, err := c.GetUserPolicy(t.Context(), &iam.GetUserPolicyInput{
		UserName: aws.String("dev"), PolicyName: aws.String("Reader"),
	})
	requireNoErr(t, err, "get user policy")
	requireEqual(t, aws.ToString(out.UserName), "dev", "UserName")
	requireEqual(t, aws.ToString(out.PolicyName), "Reader", "PolicyName")
	requireSameDoc(t, out.PolicyDocument, first, "PolicyDocument")

	// PutUserPolicy "Adds or updates an inline policy document".
	t.Run("put again updates", func(t *testing.T) {
		putUserPolicy(t, c, "dev", "Reader", second)
		got, gerr := c.GetUserPolicy(t.Context(), &iam.GetUserPolicyInput{
			UserName: aws.String("dev"), PolicyName: aws.String("Reader"),
		})
		requireNoErr(t, gerr, "get user policy")
		requireSameDoc(t, got.PolicyDocument, second, "PolicyDocument")
		requireEqual(t, len(userPolicyNames(t, c, "dev")), 2, "inline policy count")
	})

	_, err = c.DeleteUserPolicy(t.Context(), &iam.DeleteUserPolicyInput{
		UserName: aws.String("dev"), PolicyName: aws.String("Reader"),
	})
	requireNoErr(t, err, "delete user policy")
	requireSameNames(t, userPolicyNames(t, c, "dev"), []string{"Other"})

	// NoSuchEntity is in GetUserPolicy's and DeleteUserPolicy's errors.
	t.Run("deleted policy is gone", func(t *testing.T) {
		user, name := aws.String("dev"), aws.String("Reader")
		requireAs[*types.NoSuchEntityException](t, errOf(c.GetUserPolicy(t.Context(),
			&iam.GetUserPolicyInput{UserName: user, PolicyName: name})))
		requireAs[*types.NoSuchEntityException](t, errOf(c.DeleteUserPolicy(t.Context(),
			&iam.DeleteUserPolicyInput{UserName: user, PolicyName: name})))
	})

	t.Run("unknown user", func(t *testing.T) {
		err := errOf(c.PutUserPolicy(t.Context(), &iam.PutUserPolicyInput{
			UserName: aws.String("nobody"), PolicyName: aws.String("p"),
			PolicyDocument: aws.String(first),
		}))
		requireAs[*types.NoSuchEntityException](t, err)
	})

	// PutUserPolicyInput.PolicyName: 1 to 128 of [\w+=,.@-].
	t.Run("invalid policy name", func(t *testing.T) {
		err := errOf(c.PutUserPolicy(t.Context(), &iam.PutUserPolicyInput{
			UserName: aws.String("dev"), PolicyName: aws.String("a b"),
			PolicyDocument: aws.String(first),
		}))
		requireCode(t, err, codeValidation)
	})
}

func TestDeleteUserWithPolicies(t *testing.T) {
	// DeleteUser: before deleting a user, remove its "Inline policies
	// (DeleteUserPolicy)" and "Attached managed policies
	// (DetachUserPolicy)"; DeleteConflict is in its errors.
	_, c := rootIAM(t)
	arn := createPolicy(t, c, "Mine", policyDoc(allow("iam:GetUser", "*")))
	createUser(t, c, "holder")
	attachUserPolicy(t, c, "holder", arn)
	putUserPolicy(t, c, "holder", "inline", policyDoc(allow("iam:ListUsers", "*")))

	deleteUser := func() error {
		return errOf(c.DeleteUser(t.Context(), &iam.DeleteUserInput{
			UserName: aws.String("holder"),
		}))
	}

	t.Run("with both", func(t *testing.T) {
		requireAs[*types.DeleteConflictException](t, deleteUser())
		// The refused delete removed neither.
		requireSameNames(t, userPolicyNames(t, c, "holder"), []string{"inline"})
		requireEqual(t, len(attachedUserPolicies(t, c, "holder")), 1, "attached policies")
	})

	detachUserPolicy(t, c, "holder", arn)
	t.Run("with an inline policy", func(t *testing.T) {
		requireAs[*types.DeleteConflictException](t, deleteUser())
	})

	_, err := c.DeleteUserPolicy(t.Context(), &iam.DeleteUserPolicyInput{
		UserName: aws.String("holder"), PolicyName: aws.String("inline"),
	})
	requireNoErr(t, err, "delete the inline policy")

	attachUserPolicy(t, c, "holder", arn)
	t.Run("with an attached policy", func(t *testing.T) {
		requireAs[*types.DeleteConflictException](t, deleteUser())
	})
	detachUserPolicy(t, c, "holder", arn)

	requireNoErr(t, deleteUser(), "delete the user once its policies are gone")
}
