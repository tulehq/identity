//go:build e2e

package e2e

import (
	"fmt"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/iam/types"
)

// Character quotas (IAM and STS quotas, "IAM and STS character limits"),
// none of which counts white space: a managed policy, and the sum of a
// user's or a role's inline policies. Trust policy length and attachments
// are "IAM object quotas", taken at their defaults.
const (
	maxManagedPolicySize = 6144
	maxUserInlineSize    = 2048
	maxRoleInlineSize    = 10240
	maxTrustPolicySize   = 2048
	maxUserAttachments   = 10
	maxRoleAttachments   = 20
	// maxDocumentLength is the model's length bound on every
	// PolicyDocument parameter, white space included.
	maxDocumentLength = 131072
)

// sizedDoc is an identity policy of exactly n characters with no white
// space, padded in the Sid, which allows letters and digits.
func sizedDoc(t *testing.T, n int) string {
	t.Helper()
	head := `{"Version":"2012-10-17","Statement":[{"Sid":"`
	tail := `","Effect":"Allow","Action":"iam:GetUser","Resource":"*"}]}`
	pad := n - len(head) - len(tail)
	if pad < 1 {
		t.Fatalf("a document of %d characters is too short to build", n)
	}
	return head + strings.Repeat("a", pad) + tail
}

// sizedTrust is a trust policy of exactly n characters with no white space.
func sizedTrust(t *testing.T, n int) string {
	t.Helper()
	head := `{"Version":"2012-10-17","Statement":[{"Sid":"`
	tail := `","Effect":"Allow","Principal":{"AWS":"` + rootARN(defaultAccountID) +
		`"},"Action":"sts:AssumeRole"}]}`
	pad := n - len(head) - len(tail)
	if pad < 1 {
		t.Fatalf("a trust policy of %d characters is too short to build", n)
	}
	return head + strings.Repeat("a", pad) + tail
}

// spaced inserts n spaces after the document's opening brace.
func spaced(doc string, n int) string {
	return doc[:1] + strings.Repeat(" ", n) + doc[1:]
}

func TestMalformedPolicyDocuments(t *testing.T) {
	// MalformedPolicyDocument is in the errors of CreatePolicy,
	// CreatePolicyVersion and PutUserPolicy. The grammar (IAM JSON policy
	// reference) requires Statement, and in each statement Effect of Allow
	// or Deny and an Action or NotAction; the Resource element page:
	// "Statements must include either a Resource or a NotResource element";
	// the Principal element page: "You cannot use the Principal element in
	// an identity-based policy".
	_, c := rootIAM(t)
	createUser(t, c, "dev")
	arn := createPolicy(t, c, "Base", policyDoc(allow("iam:GetUser", "*")))

	docs := map[string]string{
		"not JSON":     `{not json`,
		"no Statement": `{"Version":"2012-10-17"}`,
		"no Effect":    `{"Version":"2012-10-17","Statement":{"Action":"iam:*","Resource":"*"}}`,
		"Effect Maybe": policyDoc(statement{Effect: "Maybe", Action: "iam:*", Resource: "*"}),
		"no Action":    policyDoc(statement{Effect: "Allow", Resource: "*"}),
		"no Resource":  policyDoc(statement{Effect: "Allow", Action: "iam:*"}),
		"Principal": policyDoc(statement{
			Effect: "Allow", Action: "iam:*", Resource: "*", Principal: "*",
		}),
	}
	for name, doc := range docs {
		t.Run("CreatePolicy "+name, func(t *testing.T) {
			err := errOf(c.CreatePolicy(t.Context(), &iam.CreatePolicyInput{
				PolicyName: aws.String(badName(name)), PolicyDocument: aws.String(doc),
			}))
			requireAs[*types.MalformedPolicyDocumentException](t, err)
		})
		t.Run("CreatePolicyVersion "+name, func(t *testing.T) {
			err := errOf(c.CreatePolicyVersion(t.Context(), &iam.CreatePolicyVersionInput{
				PolicyArn: aws.String(arn), PolicyDocument: aws.String(doc),
			}))
			requireAs[*types.MalformedPolicyDocumentException](t, err)
		})
		t.Run("PutUserPolicy "+name, func(t *testing.T) {
			err := errOf(c.PutUserPolicy(t.Context(), &iam.PutUserPolicyInput{
				UserName: aws.String("dev"), PolicyName: aws.String(badName(name)),
				PolicyDocument: aws.String(doc),
			}))
			requireAs[*types.MalformedPolicyDocumentException](t, err)
		})
	}

	// Nothing was stored.
	requireEqual(t, len(listVersions(t, c, arn)), 1, "versions of Base")
	requireEqual(t, len(userPolicyNames(t, c, "dev")), 0, "inline policies of dev")
	requireSameNames(t, listPolicies(t, c, &iam.ListPoliciesInput{
		Scope: types.PolicyScopeTypeLocal,
	}), []string{"Base"})
}

// badName is a policy name for a case, so that one case's document being
// accepted does not turn the next case into a duplicate name.
func badName(name string) string {
	return "Bad-" + strings.ReplaceAll(name, " ", "-")
}

func TestMalformedTrustPolicies(t *testing.T) {
	// MalformedPolicyDocument is in CreateRole's and PutRolePolicy's errors.
	// A trust policy is a resource-based policy, and "You must use the
	// Principal element in resource-based policies" (Principal element).
	_, c := rootIAM(t)
	createRole(t, c, "Worker", trustDoc(rootARN(defaultAccountID)))

	trusts := map[string]string{
		"not JSON":     `{not json`,
		"no Principal": policyDoc(statement{Effect: "Allow", Action: "sts:AssumeRole"}),
	}
	for name, doc := range trusts {
		t.Run("CreateRole "+name, func(t *testing.T) {
			err := errOf(c.CreateRole(t.Context(), &iam.CreateRoleInput{
				RoleName: aws.String("Bad"), AssumeRolePolicyDocument: aws.String(doc),
			}))
			requireAs[*types.MalformedPolicyDocumentException](t, err)
		})
	}
	requireAs[*types.NoSuchEntityException](t, errOf(c.GetRole(t.Context(),
		&iam.GetRoleInput{RoleName: aws.String("Bad")})))

	t.Run("PutRolePolicy not JSON", func(t *testing.T) {
		err := errOf(c.PutRolePolicy(t.Context(), &iam.PutRolePolicyInput{
			RoleName: aws.String("Worker"), PolicyName: aws.String("bad"),
			PolicyDocument: aws.String(`{not json`),
		}))
		requireAs[*types.MalformedPolicyDocumentException](t, err)
	})
}

func TestManagedPolicySize(t *testing.T) {
	// Assumption: a document over a character quota is LimitExceeded, which
	// CreatePolicy and CreatePolicyVersion list ("The error message
	// describes the limit exceeded"); the quotas page names no error.
	_, c := rootIAM(t)

	t.Run("at the limit", func(t *testing.T) {
		createPolicy(t, c, "Full", sizedDoc(t, maxManagedPolicySize))
	})
	t.Run("over the limit", func(t *testing.T) {
		err := errOf(c.CreatePolicy(t.Context(), &iam.CreatePolicyInput{
			PolicyName:     aws.String("Over"),
			PolicyDocument: aws.String(sizedDoc(t, maxManagedPolicySize+1)),
		}))
		requireAs[*types.LimitExceededException](t, err)
	})
	t.Run("white space is not counted", func(t *testing.T) {
		createPolicy(t, c, "Spacious", spaced(sizedDoc(t, maxManagedPolicySize), 2000))
	})
	t.Run("new version over the limit", func(t *testing.T) {
		arn := createPolicy(t, c, "Growing", sizedDoc(t, 200))
		err := errOf(c.CreatePolicyVersion(t.Context(), &iam.CreatePolicyVersionInput{
			PolicyArn:      aws.String(arn),
			PolicyDocument: aws.String(sizedDoc(t, maxManagedPolicySize+1)),
		}))
		requireAs[*types.LimitExceededException](t, err)
	})
	// The model bounds the parameter, white space included, at 131072.
	t.Run("over the parameter length", func(t *testing.T) {
		err := errOf(c.CreatePolicy(t.Context(), &iam.CreatePolicyInput{
			PolicyName:     aws.String("Huge"),
			PolicyDocument: aws.String(spaced(sizedDoc(t, 200), maxDocumentLength)),
		}))
		requireCode(t, err, codeValidation)
	})
}

func TestInlinePolicySize(t *testing.T) {
	// "the total aggregate policy size (the sum size of all inline policies)
	// per entity can't exceed": 2,048 for a user, 10,240 for a role.
	// Assumption: LimitExceeded, as for managed policies; PutUserPolicy and
	// PutRolePolicy list it.
	_, c := rootIAM(t)
	createUser(t, c, "dev")
	createRole(t, c, "Worker", trustDoc(rootARN(defaultAccountID)))

	putUser := func(name, doc string) error {
		return errOf(c.PutUserPolicy(t.Context(), &iam.PutUserPolicyInput{
			UserName: aws.String("dev"), PolicyName: aws.String(name),
			PolicyDocument: aws.String(doc),
		}))
	}
	putRole := func(name, doc string) error {
		return errOf(c.PutRolePolicy(t.Context(), &iam.PutRolePolicyInput{
			RoleName: aws.String("Worker"), PolicyName: aws.String(name),
			PolicyDocument: aws.String(doc),
		}))
	}

	t.Run("user", func(t *testing.T) {
		over := sizedDoc(t, maxUserInlineSize+1)
		requireAs[*types.LimitExceededException](t, putUser("one", over))
		full := spaced(sizedDoc(t, maxUserInlineSize), 500)
		requireNoErr(t, putUser("one", full), "put at the limit")
		requireAs[*types.LimitExceededException](t, putUser("two", sizedDoc(t, 200)))
		requireSameNames(t, userPolicyNames(t, c, "dev"), []string{"one"})
	})
	t.Run("role", func(t *testing.T) {
		over := sizedDoc(t, maxRoleInlineSize+1)
		requireAs[*types.LimitExceededException](t, putRole("one", over))
		requireNoErr(t, putRole("one", sizedDoc(t, maxRoleInlineSize)), "put at the limit")
		requireAs[*types.LimitExceededException](t, putRole("two", sizedDoc(t, 200)))
		requireSameNames(t, rolePolicyNames(t, c, "Worker"), []string{"one"})
	})
}

func TestTrustPolicySize(t *testing.T) {
	// "Role trust policy length: 2048 characters" by default. Assumptions:
	// white space is not counted, as for the character limits, and the
	// error is LimitExceeded, which CreateRole and UpdateAssumeRolePolicy
	// list.
	_, c := rootIAM(t)
	createRole(t, c, "Full", sizedTrust(t, maxTrustPolicySize))

	err := errOf(c.CreateRole(t.Context(), &iam.CreateRoleInput{
		RoleName:                 aws.String("Over"),
		AssumeRolePolicyDocument: aws.String(sizedTrust(t, maxTrustPolicySize+1)),
	}))
	requireAs[*types.LimitExceededException](t, err)

	err = errOf(c.UpdateAssumeRolePolicy(t.Context(), &iam.UpdateAssumeRolePolicyInput{
		RoleName:       aws.String("Full"),
		PolicyDocument: aws.String(sizedTrust(t, maxTrustPolicySize+1)),
	}))
	requireAs[*types.LimitExceededException](t, err)
}

func TestAttachmentLimits(t *testing.T) {
	// "Managed policies per user: 10", "per role: 20" (defaults); going past
	// a quota is LimitExceeded, in AttachUserPolicy's and AttachRolePolicy's
	// errors.
	_, c := rootIAM(t)
	createUser(t, c, "dev")
	createRole(t, c, "Worker", trustDoc(rootARN(defaultAccountID)))
	arns := make([]string, 0, maxRoleAttachments+1)
	for i := range maxRoleAttachments + 1 {
		arns = append(arns, createPolicy(t, c, fmt.Sprintf("p%02d", i),
			policyDoc(allow("iam:GetUser", "*"))))
	}

	for _, arn := range arns[:maxUserAttachments] {
		attachUserPolicy(t, c, "dev", arn)
	}
	err := errOf(c.AttachUserPolicy(t.Context(), &iam.AttachUserPolicyInput{
		UserName: aws.String("dev"), PolicyArn: aws.String(arns[maxUserAttachments]),
	}))
	requireAs[*types.LimitExceededException](t, err)
	requireEqual(t, len(attachedUserPolicies(t, c, "dev")), maxUserAttachments, "attached to dev")

	for _, arn := range arns[:maxRoleAttachments] {
		attachRolePolicy(t, c, "Worker", arn)
	}
	err = errOf(c.AttachRolePolicy(t.Context(), &iam.AttachRolePolicyInput{
		RoleName: aws.String("Worker"), PolicyArn: aws.String(arns[maxRoleAttachments]),
	}))
	requireAs[*types.LimitExceededException](t, err)
	requireEqual(t, len(attachedRolePolicies(t, c, "Worker")), maxRoleAttachments,
		"attached to Worker")
}
