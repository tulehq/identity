//go:build e2e

package e2e

import (
	"fmt"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/iam/types"
)

// maxPolicyVersions: "A managed policy can have up to five versions"
// (CreatePolicyVersion; IAM User Guide, Versioning for managed policies).
const maxPolicyVersions = 5

// versionDoc is a distinct document for the i-th version of a policy.
func versionDoc(i int) string {
	return policyDoc(allow("iam:GetUser", fmt.Sprintf("arn:aws:iam::*:user/v%d", i)))
}

func getVersion(t *testing.T, c *iam.Client, arn, id string) *types.PolicyVersion {
	t.Helper()
	out, err := c.GetPolicyVersion(t.Context(), &iam.GetPolicyVersionInput{
		PolicyArn: aws.String(arn), VersionId: aws.String(id),
	})
	requireNoErr(t, err, "get policy version "+id)
	return out.PolicyVersion
}

func TestPolicyVersionLimit(t *testing.T) {
	_, c := rootIAM(t)
	arn := createPolicy(t, c, "Versioned", versionDoc(1))

	// The CreatePolicyVersion sample response gives the second version v2,
	// and it is not the default unless SetAsDefault.
	ids := []string{"v1"}
	for i := 2; i <= maxPolicyVersions; i++ {
		id := createVersion(t, c, arn, versionDoc(i), false)
		ids = append(ids, id)
		if i == 2 {
			requireEqual(t, id, "v2", "second VersionId")
		}
	}
	versions := listVersions(t, c, arn)
	requireSameNames(t, versionIDs(versions), ids)
	requireEqual(t, defaultVersion(t, versions), "v1", "default version")

	// "If the policy has five versions, you must delete an existing version
	// using DeletePolicyVersion before you create a new version";
	// LimitExceeded is in CreatePolicyVersion's errors.
	err := errOf(c.CreatePolicyVersion(t.Context(), &iam.CreatePolicyVersionInput{
		PolicyArn: aws.String(arn), PolicyDocument: aws.String(versionDoc(6)),
	}))
	requireAs[*types.LimitExceededException](t, err)
	requireEqual(t, len(listVersions(t, c, arn)), maxPolicyVersions, "version count")

	t.Run("room again after a delete", func(t *testing.T) {
		_, err := c.DeletePolicyVersion(t.Context(), &iam.DeletePolicyVersionInput{
			PolicyArn: aws.String(arn), VersionId: aws.String(ids[1]),
		})
		requireNoErr(t, err, "delete policy version")
		requireEqual(t, len(listVersions(t, c, arn)), maxPolicyVersions-1, "version count")
		id := createVersion(t, c, arn, versionDoc(6), false)
		requireSameDoc(t, getVersion(t, c, arn, id).Document, versionDoc(6), "new Document")
	})
}

func TestSetDefaultPolicyVersion(t *testing.T) {
	_, c := rootIAM(t)
	arn := createPolicy(t, c, "Versioned", versionDoc(1))
	v2 := createVersion(t, c, arn, versionDoc(2), false)

	_, err := c.SetDefaultPolicyVersion(t.Context(), &iam.SetDefaultPolicyVersionInput{
		PolicyArn: aws.String(arn), VersionId: aws.String(v2),
	})
	requireNoErr(t, err, "set default policy version")

	requireEqual(t, aws.ToString(getPolicy(t, c, arn).DefaultVersionId), v2, "DefaultVersionId")
	requireEqual(t, defaultVersion(t, listVersions(t, c, arn)), v2, "listed default")
	requireEqual(t, getVersion(t, c, arn, v2).IsDefaultVersion, true, "v2 IsDefaultVersion")
	requireEqual(t, getVersion(t, c, arn, "v1").IsDefaultVersion, false, "v1 IsDefaultVersion")

	// CreatePolicyVersionInput.SetAsDefault: "the new policy version becomes
	// the operative version".
	t.Run("SetAsDefault", func(t *testing.T) {
		v3 := createVersion(t, c, arn, versionDoc(3), true)
		requireEqual(t, aws.ToString(getPolicy(t, c, arn).DefaultVersionId), v3,
			"DefaultVersionId")
		requireEqual(t, defaultVersion(t, listVersions(t, c, arn)), v3, "listed default")
	})

	t.Run("unknown version", func(t *testing.T) {
		err := errOf(c.SetDefaultPolicyVersion(t.Context(), &iam.SetDefaultPolicyVersionInput{
			PolicyArn: aws.String(arn), VersionId: aws.String("v9"),
		}))
		requireAs[*types.NoSuchEntityException](t, err)
	})

	// VersionId pattern: v[1-9][0-9]*(\.[A-Za-z0-9-]*)?
	t.Run("malformed version ID", func(t *testing.T) {
		err := errOf(c.SetDefaultPolicyVersion(t.Context(), &iam.SetDefaultPolicyVersionInput{
			PolicyArn: aws.String(arn), VersionId: aws.String("x1"),
		}))
		requireCode(t, err, codeValidation)
	})
}

func TestDeletePolicyVersion(t *testing.T) {
	_, c := rootIAM(t)
	arn := createPolicy(t, c, "Versioned", versionDoc(1))
	v2 := createVersion(t, c, arn, versionDoc(2), false)

	// DeletePolicyVersion: "You cannot delete the default version from a
	// policy using this operation"; DeleteConflict is in its errors.
	t.Run("the default version", func(t *testing.T) {
		err := errOf(c.DeletePolicyVersion(t.Context(), &iam.DeletePolicyVersionInput{
			PolicyArn: aws.String(arn), VersionId: aws.String("v1"),
		}))
		requireAs[*types.DeleteConflictException](t, err)
	})

	_, err := c.DeletePolicyVersion(t.Context(), &iam.DeletePolicyVersionInput{
		PolicyArn: aws.String(arn), VersionId: aws.String(v2),
	})
	requireNoErr(t, err, "delete a version that is not the default")
	requireSameNames(t, versionIDs(listVersions(t, c, arn)), []string{"v1"})

	t.Run("deleted version is gone", func(t *testing.T) {
		err := errOf(c.GetPolicyVersion(t.Context(), &iam.GetPolicyVersionInput{
			PolicyArn: aws.String(arn), VersionId: aws.String(v2),
		}))
		requireAs[*types.NoSuchEntityException](t, err)
		err = errOf(c.DeletePolicyVersion(t.Context(), &iam.DeletePolicyVersionInput{
			PolicyArn: aws.String(arn), VersionId: aws.String(v2),
		}))
		requireAs[*types.NoSuchEntityException](t, err)
	})
}

func TestDeletePolicy(t *testing.T) {
	_, c := rootIAM(t)
	arn := createPolicy(t, c, "Doomed", versionDoc(1))
	createUser(t, c, "dev")
	createRole(t, c, "Worker", trustDoc(rootARN(defaultAccountID)))

	// DeletePolicy: "you must first detach the policy from all users,
	// groups, and roles that it is attached to. In addition, you must delete
	// all the policy's versions"; DeleteConflict is in its errors.
	attachUserPolicy(t, c, "dev", arn)
	requireEqual(t, aws.ToInt32(getPolicy(t, c, arn).AttachmentCount), 1, "AttachmentCount")
	requireDeleteConflict(t, c, arn, "attached to a user")
	detachUserPolicy(t, c, "dev", arn)

	attachRolePolicy(t, c, "Worker", arn)
	requireDeleteConflict(t, c, arn, "attached to a role")
	detachRolePolicy(t, c, "Worker", arn)
	requireEqual(t, aws.ToInt32(getPolicy(t, c, arn).AttachmentCount), 0, "AttachmentCount")

	v2 := createVersion(t, c, arn, versionDoc(2), false)
	requireDeleteConflict(t, c, arn, "with a version besides the default")
	_, err := c.DeletePolicyVersion(t.Context(), &iam.DeletePolicyVersionInput{
		PolicyArn: aws.String(arn), VersionId: aws.String(v2),
	})
	requireNoErr(t, err, "delete the extra version")

	// "Delete the policy (this automatically deletes the policy's default
	// version)".
	_, err = c.DeletePolicy(t.Context(), &iam.DeletePolicyInput{PolicyArn: aws.String(arn)})
	requireNoErr(t, err, "delete policy")
	requireAs[*types.NoSuchEntityException](t, errOf(c.GetPolicy(t.Context(),
		&iam.GetPolicyInput{PolicyArn: aws.String(arn)})))
	requireAs[*types.NoSuchEntityException](t, errOf(c.GetPolicyVersion(t.Context(),
		&iam.GetPolicyVersionInput{PolicyArn: aws.String(arn), VersionId: aws.String("v1")})))

	t.Run("name is free again", func(t *testing.T) {
		createPolicy(t, c, "Doomed", versionDoc(1))
	})
}

func requireDeleteConflict(t *testing.T, c *iam.Client, arn, what string) {
	t.Helper()
	t.Run(what, func(t *testing.T) {
		err := errOf(c.DeletePolicy(t.Context(), &iam.DeletePolicyInput{
			PolicyArn: aws.String(arn),
		}))
		requireAs[*types.DeleteConflictException](t, err)
		getPolicy(t, c, arn)
	})
}
