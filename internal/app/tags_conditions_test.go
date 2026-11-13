package app

import (
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

// protectedPolicy allows every IAM action but on a user tagged protected,
// and denies creating or tagging a user with the tag key protected.
const protectedPolicy = `{"Version":"2012-10-17","Statement":[` +
	`{"Effect":"Allow","Action":"iam:*","Resource":"*"},` +
	`{"Effect":"Deny","Action":"iam:*","Resource":"*",` +
	`"Condition":{"StringEquals":{"aws:ResourceTag/protected":"true"}}},` +
	`{"Effect":"Deny","Action":["iam:CreateUser","iam:TagUser"],"Resource":"*",` +
	`"Condition":{"ForAnyValue:StringEquals":{"aws:TagKeys":["protected"]}}}]}`

func TestTagConditionKeysAreSupplied(t *testing.T) {
	ctx := t.Context()
	url := startApp(t, t.TempDir(), nil)
	root := iamClient(url, rootCreds())
	_, err := root.CreateUser(ctx, &iam.CreateUserInput{
		UserName: aws.String("boss"),
		Tags:     []iamtypes.Tag{{Key: aws.String("protected"), Value: aws.String("true")}},
	})
	check(t, err == nil, "create boss: %v", err)
	key := createUserWithKey(t, root, "ops")
	_, err = root.PutUserPolicy(ctx, &iam.PutUserPolicyInput{
		UserName: aws.String("ops"), PolicyName: aws.String("ops"),
		PolicyDocument: aws.String(protectedPolicy),
	})
	check(t, err == nil, "put the ops policy: %v", err)
	ops := iamClient(url, key)

	// aws:ResourceTag from the target user's tags.
	_, err = ops.AttachUserPolicy(ctx, &iam.AttachUserPolicyInput{
		UserName:  aws.String("boss"),
		PolicyArn: aws.String("arn:aws:iam::aws:policy/AdministratorAccess"),
	})
	requireCode(t, err, "AccessDenied")
	_, err = ops.CreateAccessKey(ctx, &iam.CreateAccessKeyInput{UserName: aws.String("boss")})
	requireCode(t, err, "AccessDenied")

	// aws:TagKeys from the request's tags.
	_, err = ops.CreateUser(ctx, &iam.CreateUserInput{
		UserName: aws.String("x"),
		Tags:     []iamtypes.Tag{{Key: aws.String("protected"), Value: aws.String("true")}},
	})
	requireCode(t, err, "AccessDenied")
	_, err = ops.CreateUser(ctx, &iam.CreateUserInput{UserName: aws.String("x")})
	check(t, err == nil, "create a user with no tags: %v", err)
}

func TestPrincipalTagsAreSupplied(t *testing.T) {
	ctx := t.Context()
	url := startApp(t, t.TempDir(), nil)
	root := iamClient(url, rootCreds())
	blueOnly := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:ListUsers",` +
		`"Resource":"*","Condition":{"StringEquals":{"aws:PrincipalTag/team":"blue"}}}]}`

	// A user's own tags.
	key := createUserWithKey(t, root, "dev")
	_, err := root.PutUserPolicy(ctx, &iam.PutUserPolicyInput{
		UserName: aws.String("dev"), PolicyName: aws.String("blue"),
		PolicyDocument: aws.String(blueOnly),
	})
	check(t, err == nil, "put the policy: %v", err)
	_, err = iamClient(url, key).ListUsers(ctx, &iam.ListUsersInput{})
	requireCode(t, err, "AccessDenied")
	_, err = root.TagUser(ctx, &iam.TagUserInput{
		UserName: aws.String("dev"),
		Tags:     []iamtypes.Tag{{Key: aws.String("team"), Value: aws.String("blue")}},
	})
	check(t, err == nil, "tag dev: %v", err)
	_, err = iamClient(url, key).ListUsers(ctx, &iam.ListUsersInput{})
	check(t, err == nil, "list users as a blue user: %v", err)

	// A session's role's tags.
	_, err = root.CreateRole(ctx, &iam.CreateRoleInput{
		RoleName:                 aws.String("blue"),
		AssumeRolePolicyDocument: aws.String(trustFor("000000000000")),
		Tags: []iamtypes.Tag{
			{Key: aws.String("team"), Value: aws.String("blue")},
		},
	})
	check(t, err == nil, "create the role: %v", err)
	_, err = root.PutRolePolicy(ctx, &iam.PutRolePolicyInput{
		RoleName: aws.String("blue"), PolicyName: aws.String("blue"),
		PolicyDocument: aws.String(blueOnly),
	})
	check(t, err == nil, "put the role policy: %v", err)
	out, err := stsClient(url, rootCreds()).AssumeRole(ctx, &sts.AssumeRoleInput{
		RoleArn:         aws.String("arn:aws:iam::000000000000:role/blue"),
		RoleSessionName: aws.String("s1"),
	})
	check(t, err == nil, "assume the role: %v", err)
	_, err = iamClient(url, sessionOf(out)).ListUsers(ctx, &iam.ListUsersInput{})
	check(t, err == nil, "list users as a session of the blue role: %v", err)
}
