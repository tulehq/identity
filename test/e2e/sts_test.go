//go:build e2e

package e2e

import (
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

// organizationRole is the one role identity lets a caller assume.
const organizationRole = "OrganizationAccountAccessRole"

func roleARN(account string) string {
	return "arn:aws:iam::" + account + ":role/" + organizationRole
}

func TestRootCallerIdentity(t *testing.T) {
	// The root user's ARN is arn:aws:iam::<account>:root, and its aws:userid
	// is the account ID (IAM User Guide, policy variables, principal table).
	srv := startServer(t, nil)

	out, err := callerIdentity(t, srv, rootCreds())
	requireNoErr(t, err, "get caller identity")
	requireEqual(t, aws.ToString(out.Account), defaultAccountID, "Account")
	requireEqual(t, aws.ToString(out.Arn), "arn:aws:iam::"+defaultAccountID+":root", "Arn")
	requireEqual(t, aws.ToString(out.UserId), defaultAccountID, "UserId")
}

func TestConfiguredAccountID(t *testing.T) {
	const account = "111122223333"
	srv := startServer(t, map[string]string{"TULE_Identity_AccountID": account})
	c := iamFor(srv, rootCreds())

	out, err := callerIdentity(t, srv, rootCreds())
	requireNoErr(t, err, "get caller identity")
	requireEqual(t, aws.ToString(out.Account), account, "Account")
	requireEqual(t, aws.ToString(out.Arn), "arn:aws:iam::"+account+":root", "Arn")

	// The root key's users belong to its account.
	created, err := c.CreateUser(t.Context(), &iam.CreateUserInput{UserName: aws.String("dev")})
	requireNoErr(t, err, "create user")
	requireUser(t, created.User, account, "/", "dev")

	key := createKey(t, c, "dev")
	got, err := callerIdentity(t, srv, key)
	requireNoErr(t, err, "get caller identity as the user")
	requireEqual(t, aws.ToString(got.Account), account, "user's Account")
}

func TestGetAccessKeyInfo(t *testing.T) {
	// GetAccessKeyInfo returns the account the key belongs to, for an IAM
	// user's key and for the root user's alike ("Access key IDs beginning
	// with AKIA are long-term credentials for an IAM user or the AWS account
	// root user").
	// The user may call it: sts:GetAccessKeyInfo needs an allowing policy
	// for an identity-issued principal (the design's breaking change).
	srv, c := rootIAM(t)
	key := userWithPolicy(t, c, "dev", policyDoc(allow("sts:GetAccessKeyInfo", "*")))
	sc := stsFor(srv, rootCreds())

	for name, id := range map[string]string{"user key": key.AccessKeyID, "root key": rootKeyID} {
		t.Run(name, func(t *testing.T) {
			out, err := sc.GetAccessKeyInfo(t.Context(), &sts.GetAccessKeyInfoInput{
				AccessKeyId: aws.String(id),
			})
			requireNoErr(t, err, "get access key info")
			requireEqual(t, aws.ToString(out.Account), defaultAccountID, "Account")
		})
	}

	t.Run("signed by the user key, about the root key", func(t *testing.T) {
		out, err := stsFor(srv, key).GetAccessKeyInfo(t.Context(), &sts.GetAccessKeyInfoInput{
			AccessKeyId: aws.String(rootKeyID),
		})
		requireNoErr(t, err, "get access key info")
		requireEqual(t, aws.ToString(out.Account), defaultAccountID, "Account")
	})

	// accessKeyIdType for GetAccessKeyInfo: 16 to 128 characters.
	t.Run("malformed key ID", func(t *testing.T) {
		err := errOf(sc.GetAccessKeyInfo(t.Context(), &sts.GetAccessKeyInfoInput{
			AccessKeyId: aws.String("short"),
		}))
		requireCode(t, err, codeValidation)
	})
}

func TestAssumeRoleWithoutAccounts(t *testing.T) {
	// The spec: without an accounts endpoint AssumeRole answers as AWS does
	// for a role that does not exist. AWS gives a caller no way to tell a
	// missing role from one it may not assume: both are AccessDenied ("User:
	// ... is not authorized to perform: sts:AssumeRole on resource: ...").
	// Assumption: the reference documents the message, not this equivalence.
	srv := startServer(t, nil)
	sc := stsFor(srv, rootCreds())

	for name, arn := range map[string]string{
		"member account":     roleARN("123456789012"),
		"management account": roleARN(defaultAccountID),
	} {
		t.Run(name, func(t *testing.T) {
			err := errOf(sc.AssumeRole(t.Context(), &sts.AssumeRoleInput{
				RoleArn:         aws.String(arn),
				RoleSessionName: aws.String("e2e"),
			}))
			requireCode(t, err, codeAccessDenied)
		})
	}
}
