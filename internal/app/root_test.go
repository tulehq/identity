package app

import (
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
)

func TestGetUserWithoutANameIsTheRootUser(t *testing.T) {
	url := startApp(t, t.TempDir(), nil)

	out, err := iamClient(url, rootCreds()).GetUser(t.Context(), &iam.GetUserInput{})
	check(t, err == nil, "get user: %v", err)
	u := out.User
	// The policy variables reference: the root user's aws:userid is the
	// account ID, and it has no user name.
	check(t, aws.ToString(u.UserId) == defaultAccount &&
		aws.ToString(u.Arn) == "arn:aws:iam::"+defaultAccount+":root" &&
		u.UserName == nil && u.Path == nil && u.CreateDate != nil,
		"root user = %+v", u)
}

func TestListAccessKeysWithoutANameListsTheRootKey(t *testing.T) {
	url := startApp(t, t.TempDir(), nil)

	out, err := iamClient(url, rootCreds()).ListAccessKeys(t.Context(),
		&iam.ListAccessKeysInput{})
	check(t, err == nil, "list access keys: %v", err)
	check(t, len(out.AccessKeyMetadata) == 1 && !out.IsTruncated, "listed = %+v", out)
	k := out.AccessKeyMetadata[0]
	check(t, aws.ToString(k.AccessKeyId) == testKeyID &&
		k.Status == iamtypes.StatusTypeActive && k.UserName == nil && k.CreateDate != nil,
		"root key = %+v", k)
}

func TestTheRootKeyCannotBeManaged(t *testing.T) {
	ctx := t.Context()
	url := startApp(t, t.TempDir(), nil)
	c := iamClient(url, rootCreds())

	_, err := c.CreateAccessKey(ctx, &iam.CreateAccessKeyInput{})
	requireCode(t, err, "InvalidInput")
	_, err = c.UpdateAccessKey(ctx, &iam.UpdateAccessKeyInput{
		AccessKeyId: aws.String(testKeyID), Status: iamtypes.StatusTypeInactive,
	})
	requireCode(t, err, "InvalidInput")
	_, err = c.DeleteAccessKey(ctx, &iam.DeleteAccessKeyInput{AccessKeyId: aws.String(testKeyID)})
	requireCode(t, err, "InvalidInput")

	// The key still signs.
	_, err = c.GetUser(ctx, &iam.GetUserInput{})
	check(t, err == nil, "get user after the refusals: %v", err)
}

func TestARoleSessionMustNameAUser(t *testing.T) {
	ctx := t.Context()
	url, out := assumeMemberRole(t)
	c := iamClient(url, aws.Credentials{
		AccessKeyID:     aws.ToString(out.Credentials.AccessKeyId),
		SecretAccessKey: aws.ToString(out.Credentials.SecretAccessKey),
		SessionToken:    aws.ToString(out.Credentials.SessionToken),
	})

	_, err := c.GetUser(ctx, &iam.GetUserInput{})
	requireCode(t, err, "ValidationError")
	_, err = c.ListAccessKeys(ctx, &iam.ListAccessKeysInput{})
	requireCode(t, err, "ValidationError")
	_, err = c.CreateAccessKey(ctx, &iam.CreateAccessKeyInput{})
	requireCode(t, err, "ValidationError")
}
