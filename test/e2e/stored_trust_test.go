//go:build e2e

package e2e

import (
	"database/sql"
	"errors"
	"os"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/iam/types"
)

// regionalRootARN is the account's root ARN with a region. An IAM ARN's
// region "is always kept blank" (IAM identifiers, IAM ARNs), so it names no
// principal; tule.dev/policy v0.1.0 took it for the account.
const regionalRootARN = "arn:aws:iam:us-east-1:" + defaultAccountID + ":root"

func TestARegionalRootARNIsRefusedAtCreateRole(t *testing.T) {
	_, root := rootIAM(t)

	_, err := root.CreateRole(t.Context(), &iam.CreateRoleInput{
		RoleName:                 aws.String("regional"),
		AssumeRolePolicyDocument: aws.String(trustDoc(regionalRootARN)),
	})
	var malformed *types.MalformedPolicyDocumentException
	if !errors.As(err, &malformed) {
		t.Fatalf("create the role: got %v, want MalformedPolicyDocument", err)
	}
	requireEqual(t, malformed.ErrorMessage(), "Invalid principal in policy", "message")

	createRole(t, root, "account", trustDoc(rootARN(defaultAccountID)))
	_, err = root.UpdateAssumeRolePolicy(t.Context(), &iam.UpdateAssumeRolePolicyInput{
		RoleName: aws.String("account"), PolicyDocument: aws.String(trustDoc(regionalRootARN)),
	})
	requireAs[*types.MalformedPolicyDocumentException](t, err)
}

func TestAStoredRegionalRootARNIsRefusedAtAssumeRole(t *testing.T) {
	srv, root := rootIAM(t)
	dev := userWithKey(t, root, "dev")
	putUserPolicy(t, root, "dev", "assume", policyDoc(allow("sts:AssumeRole", "*")))
	createRole(t, root, "legacy", trustDoc(rootARN(defaultAccountID)))
	role := iamRoleARN(defaultAccountID, "/", "legacy")
	mustAssume(t, srv, dev, role, "before")

	// An earlier identity stored the trust policy as it was sent.
	db, err := sql.Open("sqlite", "file:"+os.Getenv("TULE_Store_Path"))
	requireNoErr(t, err, "open the store")
	_, err = db.ExecContext(t.Context(), `UPDATE roles SET trust_policy = ? WHERE name = ?`,
		trustDoc(regionalRootARN), "legacy")
	requireNoErr(t, err, "store the trust policy")
	requireNoErr(t, db.Close(), "close the store")

	_, err = assumeAs(t, srv, dev, role, "after", nil)
	requireCode(t, err, codeAccessDenied)
}
