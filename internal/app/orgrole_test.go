package app

import (
	"fmt"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

func sessionOf(out *sts.AssumeRoleOutput) aws.Credentials {
	return aws.Credentials{
		AccessKeyID:     aws.ToString(out.Credentials.AccessKeyId),
		SecretAccessKey: aws.ToString(out.Credentials.SecretAccessKey),
		SessionToken:    aws.ToString(out.Credentials.SessionToken),
	}
}

func TestTheOrganizationRoleIsCreatedOnceAndOnlyWhenAllowed(t *testing.T) {
	ctx := t.Context()
	clock := &testClock{}
	url := startAppAt(t, t.TempDir(), map[string]string{
		"TULE_Identity_AccountsEndpoint": fakeAccounts(t, defaultAccount, member),
	}, clock.now)
	root := iamClient(url, rootCreds())
	rootSTS := stsClient(url, rootCreds())

	// Refused requests create nothing: a management user with no policies,
	// and a DurationSeconds over the role's maximum.
	nobody := createUserWithKey(t, root, "nobody")
	_, err := stsClient(url, nobody).AssumeRole(ctx, &sts.AssumeRoleInput{
		RoleArn: aws.String(memberRole), RoleSessionName: aws.String("s1"),
	})
	requireCode(t, err, "AccessDenied")
	_, err = rootSTS.AssumeRole(ctx, &sts.AssumeRoleInput{
		RoleArn: aws.String(memberRole), RoleSessionName: aws.String("s1"),
		DurationSeconds: aws.Int32(3601),
	})
	requireCode(t, err, "ValidationError")

	// The role is created by the first AssumeRole that passes, so after
	// the clock moves on.
	clock.advance(24 * time.Hour)
	out, err := rootSTS.AssumeRole(ctx, &sts.AssumeRoleInput{
		RoleArn: aws.String(memberRole), RoleSessionName: aws.String("s1"),
	})
	check(t, err == nil, "assume the organization role: %v", err)
	mc := iamClient(url, sessionOf(out))
	got, err := mc.GetRole(
		ctx,
		&iam.GetRoleInput{RoleName: aws.String("OrganizationAccountAccessRole")},
	)
	check(t, err == nil, "get the organization role: %v", err)
	check(t, aws.ToTime(got.Role.CreateDate).After(time.Now().Add(23*time.Hour)),
		"created %s, before the first allowed AssumeRole", aws.ToTime(got.Role.CreateDate))

	pc := deleteOrganizationRole(t, url, mc)

	// Deleted, it stays deleted.
	_, err = rootSTS.AssumeRole(ctx, &sts.AssumeRoleInput{
		RoleArn: aws.String(memberRole), RoleSessionName: aws.String("s2"),
	})
	requireCode(t, err, "AccessDenied")
	_, err = pc.GetRole(
		ctx,
		&iam.GetRoleInput{RoleName: aws.String("OrganizationAccountAccessRole")},
	)
	requireCode(t, err, "NoSuchEntity")
}

// deleteOrganizationRole has the member account, through its session mc,
// keep its own way in, a role Probe the management account may assume,
// and delete OrganizationAccountAccessRole. It returns a session of Probe.
func deleteOrganizationRole(t *testing.T, url string, mc *iam.Client) *iam.Client {
	t.Helper()
	ctx := t.Context()
	rootSTS := stsClient(url, rootCreds())
	_, err := mc.CreateRole(ctx, &iam.CreateRoleInput{
		RoleName:                 aws.String("Probe"),
		AssumeRolePolicyDocument: aws.String(trustFor("arn:aws:iam::" + defaultAccount + ":root")),
	})
	check(t, err == nil, "create Probe: %v", err)
	_, err = mc.AttachRolePolicy(ctx, &iam.AttachRolePolicyInput{
		RoleName: aws.String(
			"Probe",
		),
		PolicyArn: aws.String("arn:aws:iam::aws:policy/AdministratorAccess"),
	})
	check(t, err == nil, "attach to Probe: %v", err)
	probe, err := rootSTS.AssumeRole(ctx, &sts.AssumeRoleInput{
		RoleArn:         aws.String("arn:aws:iam::" + member + ":role/Probe"),
		RoleSessionName: aws.String("probe"),
	})
	check(t, err == nil, "assume Probe: %v", err)
	pc := iamClient(url, sessionOf(probe))
	_, err = pc.DetachRolePolicy(ctx, &iam.DetachRolePolicyInput{
		RoleName:  aws.String("OrganizationAccountAccessRole"),
		PolicyArn: aws.String("arn:aws:iam::aws:policy/AdministratorAccess"),
	})
	check(t, err == nil, "detach from the organization role: %v", err)
	_, err = pc.DeleteRole(
		ctx,
		&iam.DeleteRoleInput{RoleName: aws.String("OrganizationAccountAccessRole")},
	)
	check(t, err == nil, "delete the organization role: %v", err)

	return pc
}

func TestTheOrganizationRoleIsJudgedAsStored(t *testing.T) {
	ctx := t.Context()
	url := startApp(t, t.TempDir(), map[string]string{
		"TULE_Identity_AccountsEndpoint": fakeAccounts(t, defaultAccount, member),
	})
	rootSTS := stsClient(url, rootCreds())
	assume := func() error {
		if _, err := rootSTS.AssumeRole(ctx, &sts.AssumeRoleInput{
			RoleArn: aws.String(memberRole), RoleSessionName: aws.String("s1"),
		}); err != nil {
			return fmt.Errorf("assume the organization role: %w", err)
		}
		return nil
	}
	out, err := rootSTS.AssumeRole(ctx, &sts.AssumeRoleInput{
		RoleArn: aws.String(memberRole), RoleSessionName: aws.String("s1"),
	})
	check(t, err == nil, "assume the organization role: %v", err)

	// The member account replaces the trust policy to deny the management
	// account; the next AssumeRole is judged against it and refused.
	deny := `{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Principal":{"AWS":` +
		`"arn:aws:iam::` + defaultAccount + `:root"},"Action":"sts:AssumeRole"}]}`
	_, err = iamClient(url, sessionOf(out)).UpdateAssumeRolePolicy(ctx,
		&iam.UpdateAssumeRolePolicyInput{
			RoleName: aws.String("OrganizationAccountAccessRole"), PolicyDocument: aws.String(deny),
		})
	check(t, err == nil, "replace the trust policy: %v", err)
	requireCode(t, assume(), "AccessDenied")
}

func TestCrossAccountAssumeRoleNeedsBothSides(t *testing.T) {
	ctx := t.Context()
	url := startApp(t, t.TempDir(), map[string]string{
		"TULE_Identity_AccountsEndpoint": fakeAccounts(t, defaultAccount, member),
	})
	root := iamClient(url, rootCreds())
	alice := createUserWithKey(t, root, "alice")
	out, err := stsClient(url, rootCreds()).AssumeRole(ctx, &sts.AssumeRoleInput{
		RoleArn: aws.String(memberRole), RoleSessionName: aws.String("setup"),
	})
	check(t, err == nil, "assume the organization role: %v", err)

	// A member role whose trust policy names alice herself: a direct grant,
	// but across accounts, so alice's own policies must allow it too.
	_, err = iamClient(url, sessionOf(out)).CreateRole(ctx, &iam.CreateRoleInput{
		RoleName: aws.String("for-alice"),
		AssumeRolePolicyDocument: aws.String(
			trustFor("arn:aws:iam::" + defaultAccount + ":user/alice"),
		),
	})
	check(t, err == nil, "create the member role: %v", err)
	assume := func() error {
		if _, aErr := stsClient(url, alice).AssumeRole(ctx, &sts.AssumeRoleInput{
			RoleArn:         aws.String("arn:aws:iam::" + member + ":role/for-alice"),
			RoleSessionName: aws.String("s1"),
		}); aErr != nil {
			return fmt.Errorf("assume for-alice: %w", aErr)
		}
		return nil
	}
	requireCode(t, assume(), "AccessDenied")

	_, err = root.PutUserPolicy(ctx, &iam.PutUserPolicyInput{
		UserName: aws.String("alice"), PolicyName: aws.String("assume"),
		PolicyDocument: aws.String(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow",` +
			`"Action":"sts:AssumeRole","Resource":"arn:aws:iam::` + member + `:role/for-alice"}]}`),
	})
	check(t, err == nil, "put alice's policy: %v", err)
	check(t, assume() == nil, "assume with both sides allowing: %v", assume())
}
