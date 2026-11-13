package app

import (
	"fmt"
	neturl "net/url"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

// ownKeysPolicy lets a user list its own access keys: the resource names it
// through ${aws:username}.
const ownKeysPolicy = `{"Version":"2012-10-17","Statement":[{"Effect":"Allow",` +
	`"Action":"iam:ListAccessKeys","Resource":"arn:aws:iam::000000000000:user/${aws:username}"}]}`

// listRolesPolicy lets its holder list roles.
const listRolesPolicy = `{"Version":"2012-10-17","Statement":[{"Effect":"Allow",` +
	`"Action":"iam:ListRoles","Resource":"*"}]}`

// trustFor is a trust policy that trusts the principal.
func trustFor(principal string) string {
	return `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"` +
		principal + `"},"Action":"sts:AssumeRole"}]}`
}

func TestEveryUserPolicySourceIsEvaluatedAlike(t *testing.T) {
	ctx := t.Context()
	url := startApp(t, t.TempDir(), nil)
	root := iamClient(url, rootCreds())

	attach := map[string]func(user string){
		"inline": func(user string) {
			_, err := root.PutUserPolicy(ctx, &iam.PutUserPolicyInput{
				UserName: aws.String(user), PolicyName: aws.String("own-keys"),
				PolicyDocument: aws.String(ownKeysPolicy),
			})
			check(t, err == nil, "put user policy: %v", err)
		},
		"managed": func(user string) {
			_, err := root.AttachUserPolicy(ctx, &iam.AttachUserPolicyInput{
				UserName:  aws.String(user),
				PolicyArn: aws.String("arn:aws:iam::000000000000:policy/OwnKeys"),
			})
			check(t, err == nil, "attach user policy: %v", err)
		},
	}
	_, err := root.CreatePolicy(ctx, &iam.CreatePolicyInput{
		PolicyName: aws.String("OwnKeys"), PolicyDocument: aws.String(ownKeysPolicy),
	})
	check(t, err == nil, "create policy: %v", err)

	keys := map[string]aws.Credentials{}
	for source := range attach {
		keys[source] = createUserWithKey(t, root, "user-"+source)
	}
	for source, give := range attach {
		t.Run(source, func(t *testing.T) {
			ctx := t.Context()
			name := "user-" + source
			c := iamClient(url, keys[source])
			_, err := c.ListAccessKeys(ctx, &iam.ListAccessKeysInput{UserName: aws.String(name)})
			requireCode(t, err, "AccessDenied")

			give(name)
			_, err = c.ListAccessKeys(ctx, &iam.ListAccessKeysInput{UserName: aws.String(name)})
			check(t, err == nil, "list its own keys: %v", err)
			_, err = c.ListAccessKeys(ctx, &iam.ListAccessKeysInput{UserName: aws.String("root")})
			requireCode(t, err, "AccessDenied")
		})
	}
}

func TestEveryRolePolicySourceReachesItsSessions(t *testing.T) {
	ctx := t.Context()
	url := startApp(t, t.TempDir(), nil)
	root := iamClient(url, rootCreds())
	_, err := root.CreatePolicy(ctx, &iam.CreatePolicyInput{
		PolicyName: aws.String("ListRoles"), PolicyDocument: aws.String(listRolesPolicy),
	})
	check(t, err == nil, "create policy: %v", err)

	attach := map[string]func(role string){
		"inline": func(role string) {
			_, err := root.PutRolePolicy(ctx, &iam.PutRolePolicyInput{
				RoleName: aws.String(role), PolicyName: aws.String("list"),
				PolicyDocument: aws.String(listRolesPolicy),
			})
			check(t, err == nil, "put role policy: %v", err)
		},
		"managed": func(role string) {
			_, err := root.AttachRolePolicy(ctx, &iam.AttachRolePolicyInput{
				RoleName:  aws.String(role),
				PolicyArn: aws.String("arn:aws:iam::000000000000:policy/ListRoles"),
			})
			check(t, err == nil, "attach role policy: %v", err)
		},
	}
	for source, give := range attach {
		t.Run(source, func(t *testing.T) {
			name := "role-" + source
			_, err := root.CreateRole(ctx, &iam.CreateRoleInput{
				RoleName:                 aws.String(name),
				AssumeRolePolicyDocument: aws.String(trustFor("000000000000")),
			})
			check(t, err == nil, "create role: %v", err)
			out, err := stsClient(url, rootCreds()).AssumeRole(ctx, &sts.AssumeRoleInput{
				RoleArn:         aws.String("arn:aws:iam::000000000000:role/" + name),
				RoleSessionName: aws.String("s1"),
			})
			check(t, err == nil, "assume role: %v", err)
			session := aws.Credentials{
				AccessKeyID:     aws.ToString(out.Credentials.AccessKeyId),
				SecretAccessKey: aws.ToString(out.Credentials.SecretAccessKey),
				SessionToken:    aws.ToString(out.Credentials.SessionToken),
			}
			c := iamClient(url, session)
			_, err = c.ListRoles(ctx, &iam.ListRolesInput{})
			requireCode(t, err, "AccessDenied")

			// The session takes the role's policies as they are now.
			give(name)
			_, err = c.ListRoles(ctx, &iam.ListRolesInput{})
			check(t, err == nil, "list roles as the session: %v", err)
			_, err = c.ListUsers(ctx, &iam.ListUsersInput{})
			requireCode(t, err, "AccessDenied")
		})
	}
}

func TestAssumeRoleWithinTheAccount(t *testing.T) {
	ctx := t.Context()
	url := startApp(t, t.TempDir(), nil)
	root := iamClient(url, rootCreds())
	key := createUserWithKey(t, root, "alice")
	userARN := "arn:aws:iam::000000000000:user/alice"
	// A trust policy may only name a user that exists.
	_, err := root.CreateUser(ctx, &iam.CreateUserInput{UserName: aws.String("bob")})
	check(t, err == nil, "create user bob: %v", err)

	assume := func(role string) error {
		return assumeAs(t, url, key, role)
	}
	for role, trust := range map[string]string{
		"by-user":    trustFor(userARN),
		"by-account": trustFor("arn:aws:iam::000000000000:root"),
		"by-other":   trustFor("arn:aws:iam::000000000000:user/bob"),
	} {
		_, err = root.CreateRole(ctx, &iam.CreateRoleInput{
			RoleName: aws.String(role), AssumeRolePolicyDocument: aws.String(trust),
		})
		check(t, err == nil, "create role %s: %v", role, err)
	}

	// A trust policy that names the user is enough on its own; one that
	// names the account needs the user's own policy too; one that names
	// someone else is refused whatever the user's policies say.
	check(t, assume("by-user") == nil, "assume the role that trusts the user: %v",
		assume("by-user"))
	requireCode(t, assume("by-account"), "AccessDenied")
	requireCode(t, assume("by-other"), "AccessDenied")

	_, err = root.PutUserPolicy(ctx, &iam.PutUserPolicyInput{
		UserName: aws.String("alice"), PolicyName: aws.String("assume"),
		PolicyDocument: aws.String(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow",` +
			`"Action":"sts:AssumeRole","Resource":"*"}]}`),
	})
	check(t, err == nil, "put user policy: %v", err)
	check(t, assume("by-account") == nil, "assume the role that trusts the account: %v",
		assume("by-account"))
	requireCode(t, assume("by-other"), "AccessDenied")

	// An explicit deny in the user's policies wins over a trust policy that
	// names the user.
	_, err = root.PutUserPolicy(ctx, &iam.PutUserPolicyInput{
		UserName: aws.String("alice"), PolicyName: aws.String("deny"),
		PolicyDocument: aws.String(`{"Version":"2012-10-17","Statement":[{"Effect":"Deny",` +
			`"Action":"sts:AssumeRole","Resource":"*"}]}`),
	})
	check(t, err == nil, "put deny policy: %v", err)
	requireCode(t, assume("by-user"), "AccessDenied")
}

func TestASessionIsBoundToItsRole(t *testing.T) {
	ctx := t.Context()
	url := startApp(t, t.TempDir(), nil)
	root := iamClient(url, rootCreds())
	const roleA = "arn:aws:iam::000000000000:role/a"

	createRole := func(name, trust string) {
		t.Helper()
		_, err := root.CreateRole(ctx, &iam.CreateRoleInput{
			RoleName: aws.String(name), AssumeRolePolicyDocument: aws.String(trust),
		})
		check(t, err == nil, "create role %s: %v", name, err)
	}
	session := func(role string) aws.Credentials {
		t.Helper()
		out, err := stsClient(url, rootCreds()).AssumeRole(ctx, &sts.AssumeRoleInput{
			RoleArn: aws.String(role), RoleSessionName: aws.String("s1"),
		})
		check(t, err == nil, "assume %s: %v", role, err)
		return aws.Credentials{
			AccessKeyID:     aws.ToString(out.Credentials.AccessKeyId),
			SecretAccessKey: aws.ToString(out.Credentials.SecretAccessKey),
			SessionToken:    aws.ToString(out.Credentials.SessionToken),
		}
	}
	assumeB := func(creds aws.Credentials) error {
		if _, err := stsClient(url, creds).AssumeRole(ctx, &sts.AssumeRoleInput{
			RoleArn:         aws.String("arn:aws:iam::000000000000:role/b"),
			RoleSessionName: aws.String("chained"),
		}); err != nil {
			return fmt.Errorf("assume b: %w", err)
		}
		return nil
	}

	// Role b trusts role a by its ARN; a session of a may assume it.
	createRole("a", trustFor("000000000000"))
	createRole("b", trustFor(roleA))
	old := session(roleA)
	check(t, assumeB(old) == nil, "a session of an existing role chains: %v", assumeB(old))

	// Once a is deleted, its session is trusted by nothing.
	_, err := root.DeleteRole(ctx, &iam.DeleteRoleInput{RoleName: aws.String("a")})
	check(t, err == nil, "delete role a: %v", err)
	requireCode(t, assumeB(old), "AccessDenied")

	// A new role named a is another role: the old session gets neither its
	// policies nor its trust, while the new role's sessions get both.
	createRole("a", trustFor("000000000000"))
	_, err = root.PutRolePolicy(ctx, &iam.PutRolePolicyInput{
		RoleName: aws.String("a"), PolicyName: aws.String("list"),
		PolicyDocument: aws.String(listRolesPolicy),
	})
	check(t, err == nil, "put role policy: %v", err)
	_, err = iamClient(url, old).ListRoles(ctx, &iam.ListRolesInput{})
	requireCode(t, err, "AccessDenied")
	requireCode(t, assumeB(old), "AccessDenied")
	_, err = iamClient(url, session(roleA)).ListRoles(ctx, &iam.ListRolesInput{})
	check(t, err == nil, "list roles as the new role's session: %v", err)

	// The orphaned session still authenticates and may ask who it is.
	me, err := stsClient(url, old).GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	check(t, err == nil && aws.ToString(me.Arn) ==
		"arn:aws:sts::000000000000:assumed-role/a/s1", "caller identity = %+v, %v", me, err)
}

// assumeAs assumes the account's role with the name, signed with creds.
func assumeAs(t *testing.T, url string, creds aws.Credentials, role string) error {
	t.Helper()
	if _, err := stsClient(url, creds).AssumeRole(t.Context(), &sts.AssumeRoleInput{
		RoleArn:         aws.String("arn:aws:iam::000000000000:role/" + role),
		RoleSessionName: aws.String("s1"),
	}); err != nil {
		return fmt.Errorf("assume %s: %w", role, err)
	}
	return nil
}

// createRoleWith creates the role with the trust policy.
func createRoleWith(t *testing.T, c *iam.Client, name, trust string) error {
	t.Helper()
	if _, err := c.CreateRole(t.Context(), &iam.CreateRoleInput{
		RoleName: aws.String(name), AssumeRolePolicyDocument: aws.String(trust),
	}); err != nil {
		return fmt.Errorf("create role %s: %w", name, err)
	}
	return nil
}

// shownTrustOf is the role's trust policy as GetRole shows it, decoded.
func shownTrustOf(t *testing.T, c *iam.Client, role string) string {
	t.Helper()
	out, err := c.GetRole(t.Context(), &iam.GetRoleInput{RoleName: aws.String(role)})
	check(t, err == nil, "get role %s: %v", role, err)
	doc, err := url2doc(aws.ToString(out.Role.AssumeRolePolicyDocument))
	check(t, err == nil, "decode the trust policy: %v", err)
	return doc
}

func TestTrustPoliciesNameUniqueIDs(t *testing.T) {
	ctx := t.Context()
	url := startApp(t, t.TempDir(), nil)
	root := iamClient(url, rootCreds())
	const aliceARN = "arn:aws:iam::000000000000:user/alice"
	createRole := func(name, trust string) error { return createRoleWith(t, root, name, trust) }
	assume := func(creds aws.Credentials, role string) error {
		return assumeAs(t, url, creds, role)
	}
	trustDoc := func(role string) string { return shownTrustOf(t, root, role) }

	// A trust policy that names a user or role no one has is refused, at
	// CreateRole and at UpdateAssumeRolePolicy; accounts and "*" are not
	// bound.
	err := createRole("ghost", trustFor(aliceARN))
	requireCode(t, err, "MalformedPolicyDocument")
	check(t, createRole("open", trustFor("*")) == nil, "a trust policy for everyone")
	_, err = root.UpdateAssumeRolePolicy(ctx, &iam.UpdateAssumeRolePolicyInput{
		RoleName: aws.String("open"), PolicyDocument: aws.String(trustFor(aliceARN)),
	})
	requireCode(t, err, "MalformedPolicyDocument")

	// The role trusts alice as she is now.
	alice := createUserWithKey(t, root, "alice")
	check(t, createRole("for-alice", trustFor(aliceARN)) == nil, "create the role for alice")
	check(t, assume(alice, "for-alice") == nil, "alice assumes the role: %v",
		assume(alice, "for-alice"))

	// Deleted, she is shown as her unique ID; a new alice is not trusted.
	me, err := iamClient(url, rootCreds()).GetUser(ctx, &iam.GetUserInput{
		UserName: aws.String("alice"),
	})
	check(t, err == nil, "get alice: %v", err)
	oldID := aws.ToString(me.User.UserId)
	deleteUser(t, root, "alice", alice.AccessKeyID)
	check(t, strings.Contains(trustDoc("for-alice"), `"AWS":"`+oldID+`"`) &&
		!strings.Contains(trustDoc("for-alice"), aliceARN),
		"trust policy after the user is deleted = %s", trustDoc("for-alice"))
	newAlice := createUserWithKey(t, root, "alice")
	requireCode(t, assume(newAlice, "for-alice"), "AccessDenied")

	// Saving the trust policy again binds the new alice.
	_, err = root.UpdateAssumeRolePolicy(ctx, &iam.UpdateAssumeRolePolicyInput{
		RoleName: aws.String("for-alice"), PolicyDocument: aws.String(trustFor(aliceARN)),
	})
	check(t, err == nil, "update the trust policy: %v", err)
	check(t, assume(newAlice, "for-alice") == nil, "the new alice assumes the role: %v",
		assume(newAlice, "for-alice"))
}

func TestARecreatedRoleIsNotTrustedByChaining(t *testing.T) {
	ctx := t.Context()
	url := startApp(t, t.TempDir(), nil)
	root := iamClient(url, rootCreds())
	const roleA = "arn:aws:iam::000000000000:role/a"

	for _, r := range []struct{ name, trust string }{
		{"a", trustFor("000000000000")},
		{"b", trustFor(roleA)},
	} {
		_, err := root.CreateRole(ctx, &iam.CreateRoleInput{
			RoleName: aws.String(r.name), AssumeRolePolicyDocument: aws.String(r.trust),
		})
		check(t, err == nil, "create role %s: %v", r.name, err)
	}
	chain := func() error {
		out, err := stsClient(url, rootCreds()).AssumeRole(ctx, &sts.AssumeRoleInput{
			RoleArn: aws.String(roleA), RoleSessionName: aws.String("s1"),
		})
		check(t, err == nil, "assume a: %v", err)
		if _, err = stsClient(url, aws.Credentials{
			AccessKeyID:     aws.ToString(out.Credentials.AccessKeyId),
			SecretAccessKey: aws.ToString(out.Credentials.SecretAccessKey),
			SessionToken:    aws.ToString(out.Credentials.SessionToken),
		}).AssumeRole(ctx, &sts.AssumeRoleInput{
			RoleArn:         aws.String("arn:aws:iam::000000000000:role/b"),
			RoleSessionName: aws.String("chained"),
		}); err != nil {
			return fmt.Errorf("assume b: %w", err)
		}
		return nil
	}
	check(t, chain() == nil, "a session of a chains into b: %v", chain())

	// A role a created again is not the role b trusts.
	_, err := root.DeleteRole(ctx, &iam.DeleteRoleInput{RoleName: aws.String("a")})
	check(t, err == nil, "delete role a: %v", err)
	_, err = root.CreateRole(ctx, &iam.CreateRoleInput{
		RoleName: aws.String("a"), AssumeRolePolicyDocument: aws.String(trustFor("000000000000")),
	})
	check(t, err == nil, "create role a again: %v", err)
	requireCode(t, chain(), "AccessDenied")
}

// url2doc decodes a policy document IAM returned URL-encoded.
func url2doc(encoded string) (string, error) {
	doc, err := neturl.QueryUnescape(encoded)
	if err != nil {
		return "", fmt.Errorf("unescape: %w", err)
	}
	return doc, nil
}

// deleteUser deletes the user and its one access key.
func deleteUser(t *testing.T, c *iam.Client, name, keyID string) {
	t.Helper()
	_, err := c.DeleteAccessKey(t.Context(), &iam.DeleteAccessKeyInput{
		UserName: aws.String(name), AccessKeyId: aws.String(keyID),
	})
	check(t, err == nil, "delete the key of %s: %v", name, err)
	_, err = c.DeleteUser(t.Context(), &iam.DeleteUserInput{UserName: aws.String(name)})
	check(t, err == nil, "delete user %s: %v", name, err)
}

// euWestOnly allows listing users only in eu-west-1, as a policy that
// confines a principal to a region does.
const euWestOnly = `{"Version":"2012-10-17","Statement":[{"Effect":"Allow",` +
	`"Action":"iam:ListUsers","Resource":"*",` +
	`"Condition":{"StringEquals":{"aws:RequestedRegion":"eu-west-1"}}}]}`

// usEastOnly allows listing users only in us-east-1.
const usEastOnly = `{"Version":"2012-10-17","Statement":[{"Effect":"Allow",` +
	`"Action":"iam:ListUsers","Resource":"*",` +
	`"Condition":{"StringEquals":{"aws:RequestedRegion":"us-east-1"}}}]}`

// aws:RequestedRegion is us-east-1, where IAM's one endpoint is, whatever
// region a request's credential is scoped to: the caller does not choose it.
func TestTheRequestedRegionIsUSEast1(t *testing.T) {
	url := startApp(t, t.TempDir(), nil)
	root := iamClient(url, rootCreds())
	inRegion := func(region string) func(*iam.Options) {
		return func(o *iam.Options) { o.Region = region }
	}
	for name, tc := range map[string]struct {
		policy, region string
		allowed        bool
	}{
		"eu-west-1 policy, eu-west-1 scope": {euWestOnly, "eu-west-1", false},
		"eu-west-1 policy, us-east-1 scope": {euWestOnly, "us-east-1", false},
		"us-east-1 policy, eu-west-1 scope": {usEastOnly, "eu-west-1", true},
		"us-east-1 policy, us-east-1 scope": {usEastOnly, "us-east-1", true},
	} {
		t.Run(name, func(t *testing.T) {
			ctx := t.Context()
			user := strings.NewReplacer(" ", "", ",", "-").Replace(name)
			key := createUserWithKey(t, root, user)
			_, err := root.PutUserPolicy(ctx, &iam.PutUserPolicyInput{
				UserName: aws.String(user), PolicyName: aws.String("region"),
				PolicyDocument: aws.String(tc.policy),
			})
			check(t, err == nil, "put the policy: %v", err)
			_, err = iamClient(url, key).ListUsers(ctx, &iam.ListUsersInput{},
				inRegion(tc.region))
			if tc.allowed {
				check(t, err == nil, "list users: %v", err)
			} else {
				requireCode(t, err, "AccessDenied")
			}
		})
	}
}
