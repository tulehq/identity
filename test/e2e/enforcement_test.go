//go:build e2e

package e2e

import (
	"errors"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/aws/smithy-go"
)

// denial is what an AccessDenied message must say. The IAM User Guide,
// "Troubleshoot access denied error messages": the format is "User <user>
// is not authorized to perform <action> on <resource> because <context>",
// shown in its examples as "User: <arn> is not authorized to perform:
// <action> on resource: <arn> ...", with "because no identity-based policy
// allows the <action> action" for an implicit deny and "with an explicit
// deny in an identity-based policy" (optionally ": <policy ARN>") for an
// explicit one. The design quotes the same forms.
type denial struct {
	principal string
	action    string
	// resource is the ARN the message must name. Empty for an action with
	// no resource type (service authorization reference: ListUsers), where
	// the reference does not show what IAM names, so it is not checked.
	resource string
	explicit bool
}

func requireDenied(t *testing.T, err error, d denial) {
	t.Helper()
	requireCode(t, err, codeAccessDenied)
	var apiErr smithy.APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("not an API error: %v", err)
	}
	msg := apiErr.ErrorMessage()
	head := "User: " + d.principal + " is not authorized to perform: " + d.action
	if d.resource != "" {
		head += " on resource: " + d.resource
	}
	if !strings.HasPrefix(msg, head) {
		t.Fatalf("message %q does not start with %q", msg, head)
	}
	if d.explicit {
		const ctx = " with an explicit deny in an identity-based policy"
		if !strings.Contains(msg, ctx) {
			t.Fatalf("message %q does not contain %q", msg, ctx)
		}
		return
	}
	tail := " because no identity-based policy allows the " + d.action + " action"
	if !strings.HasSuffix(msg, tail) {
		t.Fatalf("message %q does not end with %q", msg, tail)
	}
	if d.resource != "" && msg != head+tail {
		t.Fatalf("message %q, want %q", msg, head+tail)
	}
}

// devARN is the ARN of a user named name at the default path.
func devARN(name string) string {
	return userARN(defaultAccountID, "/", name)
}

func TestNoPolicyDeniesIAM(t *testing.T) {
	// The design: with no policy allowing it, an identity-issued principal's
	// request is denied. CreateUser's resource is the user it creates
	// (service authorization reference, resource type "user").
	srv, c := rootIAM(t)
	uc := iamFor(srv, userWithKey(t, c, "plain"))

	t.Run("ListUsers", func(t *testing.T) {
		requireDenied(t, errOf(uc.ListUsers(t.Context(), &iam.ListUsersInput{})),
			denial{principal: devARN("plain"), action: "iam:ListUsers"})
	})
	t.Run("CreateUser", func(t *testing.T) {
		err := errOf(uc.CreateUser(t.Context(), &iam.CreateUserInput{
			UserName: aws.String("sneaky"),
		}))
		requireDenied(t, err, denial{
			principal: devARN("plain"), action: "iam:CreateUser", resource: devARN("sneaky"),
		})
	})
	requireAs[*types.NoSuchEntityException](t, errOf(c.GetUser(t.Context(),
		&iam.GetUserInput{UserName: aws.String("sneaky")})))
}

func TestAllowedActionOnly(t *testing.T) {
	srv, c := rootIAM(t)
	key := userWithPolicy(t, c, "lister", policyDoc(allow("iam:ListUsers", "*")))
	uc := iamFor(srv, key)

	out, err := uc.ListUsers(t.Context(), &iam.ListUsersInput{})
	requireNoErr(t, err, "list users with iam:ListUsers allowed")
	requireSameNames(t, userNames(out.Users), []string{"lister"})

	err = errOf(uc.CreateUser(t.Context(), &iam.CreateUserInput{UserName: aws.String("x")}))
	requireDenied(t, err, denial{
		principal: devARN("lister"), action: "iam:CreateUser", resource: devARN("x"),
	})

	// Action names are matched without regard to case, with * wildcards
	// (IAM JSON policy elements: Action).
	t.Run("wildcard and case", func(t *testing.T) {
		k := userWithPolicy(t, c, "getter", policyDoc(allow("IAM:get*", "*")))
		_, err := iamFor(srv, k).GetUser(t.Context(), &iam.GetUserInput{
			UserName: aws.String("lister"),
		})
		requireNoErr(t, err, "get user with IAM:get* allowed")
	})
}

func TestExplicitDenyWins(t *testing.T) {
	// Policy evaluation logic: an explicit deny in any policy overrides any
	// allow. The Allow is attached managed and the Deny inline, so the two
	// come from different policies.
	srv, c := rootIAM(t)
	createUser(t, c, "dev")
	attachUserPolicy(t, c, "dev", createPolicy(t, c, "AllIAM", policyDoc(allow("iam:*", "*"))))
	putUserPolicy(t, c, "dev", "NoCreate", policyDoc(deny("iam:CreateUser")))
	uc := iamFor(srv, createKey(t, c, "dev"))

	_, err := uc.ListUsers(t.Context(), &iam.ListUsersInput{})
	requireNoErr(t, err, "list users, allowed and not denied")

	err = errOf(uc.CreateUser(t.Context(), &iam.CreateUserInput{UserName: aws.String("x")}))
	requireDenied(t, err, denial{
		principal: devARN("dev"), action: "iam:CreateUser", resource: devARN("x"), explicit: true,
	})
}

func TestResourceScopedAllow(t *testing.T) {
	// CreateAccessKey's resource is the user whose key it creates.
	srv, c := rootIAM(t)
	createUser(t, c, "other")
	key := userWithPolicy(t, c, "self",
		policyDoc(allow("iam:CreateAccessKey", devARN("self"))))
	uc := iamFor(srv, key)

	_, err := uc.CreateAccessKey(t.Context(), &iam.CreateAccessKeyInput{
		UserName: aws.String("self"),
	})
	requireNoErr(t, err, "create an access key for itself")

	err = errOf(uc.CreateAccessKey(t.Context(), &iam.CreateAccessKeyInput{
		UserName: aws.String("other"),
	}))
	requireDenied(t, err, denial{
		principal: devARN("self"), action: "iam:CreateAccessKey", resource: devARN("other"),
	})
	requireEqual(t, len(listKeys(t, c, "other")), 0, "keys of other")
}

func TestUsernamePolicyVariable(t *testing.T) {
	// Policy variables: ${aws:username} is an IAM user's name, usable in the
	// resource part of an ARN, when Version is 2012-10-17. One managed
	// policy serves both users.
	srv, c := rootIAM(t)
	own := createPolicy(t, c, "OwnKeys", policyDoc(
		allow([]string{"iam:CreateAccessKey", "iam:ListAccessKeys"},
			"arn:aws:iam::"+defaultAccountID+":user/${aws:username}")))
	keys := map[string]aws.Credentials{}
	for _, name := range []string{"alice", "bob"} {
		createUser(t, c, name)
		attachUserPolicy(t, c, name, own)
		keys[name] = createKey(t, c, name)
	}

	for self, other := range map[string]string{"alice": "bob", "bob": "alice"} {
		t.Run(self, func(t *testing.T) {
			uc := iamFor(srv, keys[self])
			_, err := uc.ListAccessKeys(t.Context(), &iam.ListAccessKeysInput{
				UserName: aws.String(self),
			})
			requireNoErr(t, err, "list its own keys")
			err = errOf(uc.ListAccessKeys(t.Context(), &iam.ListAccessKeysInput{
				UserName: aws.String(other),
			}))
			requireDenied(t, err, denial{
				principal: devARN(self), action: "iam:ListAccessKeys", resource: devARN(other),
			})
		})
	}

	// "If you don't include the Version element ..., variables like
	// ${aws:username} are treated as literal strings in the policy."
	t.Run("without Version the variable is literal", func(t *testing.T) {
		doc := `{"Statement":[{"Effect":"Allow","Action":"iam:ListAccessKeys",` +
			`"Resource":"arn:aws:iam::` + defaultAccountID + `:user/${aws:username}"}]}`
		k := userWithPolicy(t, c, "carol", doc)
		err := errOf(iamFor(srv, k).ListAccessKeys(t.Context(), &iam.ListAccessKeysInput{
			UserName: aws.String("carol"),
		}))
		requireDenied(t, err, denial{
			principal: devARN("carol"), action: "iam:ListAccessKeys", resource: devARN("carol"),
		})
	})
}

func TestDefaultVersionIsEnforced(t *testing.T) {
	// The default version "is the version that is in effect for the IAM
	// users, groups, and roles to which the policy is attached"
	// (CreatePolicyVersion); SetDefaultPolicyVersion "affects all users,
	// groups, and roles that the policy is attached to".
	srv, c := rootIAM(t)
	arn := createPolicy(t, c, "Switch", policyDoc(allow("iam:ListUsers", "*")))
	createUser(t, c, "dev")
	attachUserPolicy(t, c, "dev", arn)
	uc := iamFor(srv, createKey(t, c, "dev"))
	listUsers := func() error { return errOf(uc.ListUsers(t.Context(), &iam.ListUsersInput{})) }

	requireNoErr(t, listUsers(), "list users under v1")
	v2 := createVersion(t, c, arn, policyDoc(allow("iam:GetUser", "*")), false)
	requireNoErr(t, listUsers(), "list users while v1 is still the default")

	_, err := c.SetDefaultPolicyVersion(t.Context(), &iam.SetDefaultPolicyVersionInput{
		PolicyArn: aws.String(arn), VersionId: aws.String(v2),
	})
	requireNoErr(t, err, "set v2 as default")
	requireDenied(t, listUsers(), denial{principal: devARN("dev"), action: "iam:ListUsers"})

	// Detaching takes the permissions away.
	detachUserPolicy(t, c, "dev", arn)
	requireDenied(t, errOf(uc.GetUser(t.Context(), &iam.GetUserInput{
		UserName: aws.String("dev"),
	})), denial{principal: devARN("dev"), action: "iam:GetUser", resource: devARN("dev")})
}

func TestAdministratorAccessGrantsIAM(t *testing.T) {
	srv, c := rootIAM(t)
	createUser(t, c, "admin")
	attachUserPolicy(t, c, "admin", adminAccessARN)
	ac := iamFor(srv, createKey(t, c, "admin"))

	createUser(t, ac, "made-by-admin")
	arn := createPolicy(t, ac, "AdminMade", policyDoc(allow("iam:GetUser", "*")))
	attachUserPolicy(t, ac, "made-by-admin", arn)
	putUserPolicy(t, ac, "made-by-admin", "inline", policyDoc(allow("iam:ListUsers", "*")))
	createRole(t, ac, "AdminRole", trustDoc(rootARN(defaultAccountID)))
	createKey(t, ac, "made-by-admin")
	out, err := ac.ListUsers(t.Context(), &iam.ListUsersInput{})
	requireNoErr(t, err, "list users as admin")
	requireSameNames(t, userNames(out.Users), []string{"admin", "made-by-admin"})
}

func TestGetCallerIdentityIsAlwaysAllowed(t *testing.T) {
	// GetCallerIdentity: "No permissions are required to perform this
	// operation. If an administrator attaches a policy to your identity that
	// explicitly denies access to the sts:GetCallerIdentity action, you can
	// still perform this operation."
	srv, c := rootIAM(t)
	for name, doc := range map[string]string{
		"no policy":     "",
		"explicit deny": policyDoc(deny("sts:GetCallerIdentity"), deny("*")),
	} {
		t.Run(name, func(t *testing.T) {
			user := strings.ReplaceAll(name, " ", "-")
			createUser(t, c, user)
			if doc != "" {
				putUserPolicy(t, c, user, "deny", doc)
			}
			out, err := callerIdentity(t, srv, createKey(t, c, user))
			requireNoErr(t, err, "get caller identity")
			requireEqual(t, aws.ToString(out.Arn), devARN(user), "Arn")
		})
	}
}

func TestGetAccessKeyInfoNeedsPolicy(t *testing.T) {
	// The service authorization reference lists sts:GetAccessKeyInfo as an
	// action (Read), and nothing exempts it as GetCallerIdentity is; under
	// the design a principal no policy allows is denied it.
	srv, c := rootIAM(t)
	plain := userWithKey(t, c, "plain")
	allowed := userWithPolicy(t, c, "allowed", policyDoc(allow("sts:GetAccessKeyInfo", "*")))
	in := &sts.GetAccessKeyInfoInput{AccessKeyId: aws.String(rootKeyID)}

	requireDenied(t, errOf(stsFor(srv, plain).GetAccessKeyInfo(t.Context(), in)),
		denial{principal: devARN("plain"), action: "sts:GetAccessKeyInfo"})

	out, err := stsFor(srv, allowed).GetAccessKeyInfo(t.Context(), in)
	requireNoErr(t, err, "get access key info with the action allowed")
	requireEqual(t, aws.ToString(out.Account), defaultAccountID, "Account")
}

func TestRootIsNotEvaluated(t *testing.T) {
	// The design: the root principal is never evaluated against policies.
	// Root has no policies of its own, so root's calls succeeding while a
	// deny-everything policy exists in the account (attached to a user) is
	// the check.
	srv, c := rootIAM(t)
	createUser(t, c, "dev")
	arn := createPolicy(t, c, "P", policyDoc(deny("*")))
	attachUserPolicy(t, c, "dev", arn)
	createRole(t, c, "R", trustDoc(rootARN(defaultAccountID)))
	_, err := c.ListUsers(t.Context(), &iam.ListUsersInput{})
	requireNoErr(t, err, "list users as root")
	_, err = stsFor(srv, rootCreds()).GetAccessKeyInfo(t.Context(),
		&sts.GetAccessKeyInfoInput{AccessKeyId: aws.String(rootKeyID)})
	requireNoErr(t, err, "get access key info as root")
}
