package app

import (
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	ststypes "github.com/aws/aws-sdk-go-v2/service/sts/types"
)

func TestRoleChainingIsCappedAtAnHour(t *testing.T) {
	ctx := t.Context()
	url := startApp(t, t.TempDir(), nil)
	root := iamClient(url, rootCreds())
	for _, name := range []string{"a", "b"} {
		_, err := root.CreateRole(ctx, &iam.CreateRoleInput{
			RoleName:                 aws.String(name),
			AssumeRolePolicyDocument: aws.String(trustFor("000000000000")),
			MaxSessionDuration:       aws.Int32(43200),
		})
		check(t, err == nil, "create role %s: %v", name, err)
	}
	_, err := root.PutRolePolicy(ctx, &iam.PutRolePolicyInput{
		RoleName: aws.String("a"), PolicyName: aws.String("assume"),
		PolicyDocument: aws.String(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow",` +
			`"Action":"sts:AssumeRole","Resource":"*"}]}`),
	})
	check(t, err == nil, "put role policy: %v", err)

	// The root user may assume a for longer than an hour; a session of a
	// may assume b for an hour at most.
	out, err := stsClient(url, rootCreds()).AssumeRole(ctx, &sts.AssumeRoleInput{
		RoleArn:         aws.String("arn:aws:iam::000000000000:role/a"),
		RoleSessionName: aws.String("s1"), DurationSeconds: aws.Int32(7200),
	})
	check(t, err == nil, "assume a for two hours: %v", err)
	chained := stsClient(url, sessionOf(out))
	for d, want := range map[int32]string{3600: "", 3601: "ValidationError"} {
		_, err = chained.AssumeRole(ctx, &sts.AssumeRoleInput{
			RoleArn:         aws.String("arn:aws:iam::000000000000:role/b"),
			RoleSessionName: aws.String("chained"), DurationSeconds: aws.Int32(d),
		})
		if want == "" {
			check(t, err == nil, "chain for %ds: %v", d, err)
		} else {
			requireCode(t, err, want)
		}
	}
}

func TestExternalIDIsAConditionKey(t *testing.T) {
	ctx := t.Context()
	url := startApp(t, t.TempDir(), nil)
	root := iamClient(url, rootCreds())
	key := createUserWithKey(t, root, "dev")
	trust := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":` +
		`"arn:aws:iam::000000000000:user/dev"},"Action":"sts:AssumeRole",` +
		`"Condition":{"StringEquals":{"sts:ExternalId":"secret"}}}]}`
	_, err := root.CreateRole(ctx, &iam.CreateRoleInput{
		RoleName: aws.String("ext"), AssumeRolePolicyDocument: aws.String(trust),
	})
	check(t, err == nil, "create role: %v", err)

	for id, want := range map[string]string{"secret": "", "wrong": "AccessDenied", "": "AccessDenied"} {
		in := &sts.AssumeRoleInput{
			RoleArn: aws.String(
				"arn:aws:iam::000000000000:role/ext",
			),
			RoleSessionName: aws.String("s1"),
		}
		if id != "" {
			in.ExternalId = aws.String(id)
		}
		_, err = stsClient(url, key).AssumeRole(ctx, in)
		if want == "" {
			check(t, err == nil, "assume with ExternalId %q: %v", id, err)
		} else {
			requireCode(t, err, want)
		}
	}
}

func TestSessionTagsAndSourceIdentityAreRefused(t *testing.T) {
	ctx := t.Context()
	url := startApp(t, t.TempDir(), nil)
	_, err := iamClient(url, rootCreds()).CreateRole(ctx, &iam.CreateRoleInput{
		RoleName: aws.String("r"), AssumeRolePolicyDocument: aws.String(trustFor("000000000000")),
	})
	check(t, err == nil, "create role: %v", err)
	for name, in := range map[string]*sts.AssumeRoleInput{
		"Tags": {Tags: []ststypes.Tag{{Key: aws.String("k"), Value: aws.String("v")}}},
		"TransitiveTagKeys": {
			Tags:              []ststypes.Tag{{Key: aws.String("k"), Value: aws.String("v")}},
			TransitiveTagKeys: []string{"k"},
		},
		"SourceIdentity": {SourceIdentity: aws.String("dev")},
	} {
		in.RoleArn = aws.String("arn:aws:iam::000000000000:role/r")
		in.RoleSessionName = aws.String("s1")
		_, err = stsClient(url, rootCreds()).AssumeRole(ctx, in)
		if err == nil {
			t.Errorf("%s was accepted", name)
			continue
		}
		requireCode(t, err, "InvalidParameterValue")
	}
}
