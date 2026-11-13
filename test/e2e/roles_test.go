//go:build e2e

package e2e

import (
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/iam/types"
)

// defaultMaxSession is MaxSessionDuration when CreateRole is given none:
// "the default value of one hour is applied".
const defaultMaxSession = 3600

// rootARN is the account principal's ARN, arn:aws:iam::<account>:root
// (Principal element, AWS account principals).
func rootARN(account string) string {
	return "arn:aws:iam::" + account + ":root"
}

// iamRoleARN is a role's ARN, arn:aws:iam::<account>:role/<path><name>
// (CreateRole's sample response).
func iamRoleARN(account, path, name string) string {
	return "arn:aws:iam::" + account + ":role" + path + name
}

// createRole creates a role at the default path with trust as its trust
// policy.
func createRole(t *testing.T, c *iam.Client, name, trust string) {
	t.Helper()
	_, err := c.CreateRole(t.Context(), &iam.CreateRoleInput{
		RoleName: aws.String(name), AssumeRolePolicyDocument: aws.String(trust),
	})
	requireNoErr(t, err, "create role "+name)
}

func getRole(t *testing.T, c *iam.Client, name string) *types.Role {
	t.Helper()
	out, err := c.GetRole(t.Context(), &iam.GetRoleInput{RoleName: aws.String(name)})
	requireNoErr(t, err, "get role "+name)
	if out.Role == nil {
		t.Fatalf("get role %s returned no role", name)
	}
	return out.Role
}

func attachRolePolicy(t *testing.T, c *iam.Client, role, arn string) {
	t.Helper()
	_, err := c.AttachRolePolicy(t.Context(), &iam.AttachRolePolicyInput{
		RoleName: aws.String(role), PolicyArn: aws.String(arn),
	})
	requireNoErr(t, err, "attach "+arn+" to role "+role)
}

func detachRolePolicy(t *testing.T, c *iam.Client, role, arn string) {
	t.Helper()
	_, err := c.DetachRolePolicy(t.Context(), &iam.DetachRolePolicyInput{
		RoleName: aws.String(role), PolicyArn: aws.String(arn),
	})
	requireNoErr(t, err, "detach "+arn+" from role "+role)
}

func putRolePolicy(t *testing.T, c *iam.Client, role, name, doc string) {
	t.Helper()
	_, err := c.PutRolePolicy(t.Context(), &iam.PutRolePolicyInput{
		RoleName: aws.String(role), PolicyName: aws.String(name), PolicyDocument: aws.String(doc),
	})
	requireNoErr(t, err, "put role policy "+name+" on "+role)
}

func attachedRolePolicies(t *testing.T, c *iam.Client, role string) []types.AttachedPolicy {
	t.Helper()
	out, err := c.ListAttachedRolePolicies(t.Context(), &iam.ListAttachedRolePoliciesInput{
		RoleName: aws.String(role),
	})
	requireNoErr(t, err, "list attached role policies of "+role)
	return out.AttachedPolicies
}

func rolePolicyNames(t *testing.T, c *iam.Client, role string) []string {
	t.Helper()
	out, err := c.ListRolePolicies(t.Context(), &iam.ListRolePoliciesInput{
		RoleName: aws.String(role),
	})
	requireNoErr(t, err, "list role policies of "+role)
	return out.PolicyNames
}

// requireRole checks the fields every Role carries.
func requireRole(t *testing.T, r *types.Role, path, name, trust string) {
	t.Helper()
	if r == nil {
		t.Fatal("no role returned")
	}
	requireEqual(t, aws.ToString(r.RoleName), name, "RoleName")
	requireEqual(t, aws.ToString(r.Path), path, "Path")
	requireEqual(t, aws.ToString(r.Arn), iamRoleARN(defaultAccountID, path, name), "Arn")
	requireMatch(t, roleIDPattern, aws.ToString(r.RoleId), "RoleId")
	if r.CreateDate == nil {
		t.Fatal("no CreateDate")
	}
	// CreateRoleInput.AssumeRolePolicyDocument: "Upon success, the response
	// includes the same trust policy in JSON format."
	requireSameDoc(t, r.AssumeRolePolicyDocument, trust, "AssumeRolePolicyDocument")
}

func TestCreateRole(t *testing.T) {
	_, c := rootIAM(t)
	trust := trustDoc(rootARN(defaultAccountID))
	path := "/application_abc/component_xyz/"
	before := time.Now()

	out, err := c.CreateRole(t.Context(), &iam.CreateRoleInput{
		RoleName:                 aws.String("S3Access"),
		AssumeRolePolicyDocument: aws.String(trust),
		Path:                     aws.String(path),
		Description:              aws.String("reads the bucket"),
		MaxSessionDuration:       aws.Int32(7200),
		Tags:                     []types.Tag{tag("team", "platform")},
	})
	requireNoErr(t, err, "create role")
	requireRole(t, out.Role, path, "S3Access", trust)
	requireRecent(t, out.Role.CreateDate, before, time.Now(), "CreateDate")

	t.Run("GetRole agrees", func(t *testing.T) {
		got := getRole(t, c, "S3Access")
		requireRole(t, got, path, "S3Access", trust)
		requireEqual(t, aws.ToString(got.RoleId), aws.ToString(out.Role.RoleId), "RoleId")
		requireEqual(t, aws.ToString(got.Description), "reads the bucket", "Description")
		requireEqual(t, aws.ToInt32(got.MaxSessionDuration), 7200, "MaxSessionDuration")
		requireTags(t, got.Tags, map[string]string{"team": "platform"}, "Tags")
	})

	t.Run("ListRoles agrees", func(t *testing.T) {
		got, err := c.ListRoles(t.Context(), &iam.ListRolesInput{})
		requireNoErr(t, err, "list roles")
		requireSameNames(t, roleNames(got.Roles), []string{"S3Access"})
		requireEqual(t, aws.ToString(got.Roles[0].Arn), aws.ToString(out.Role.Arn), "Arn")
	})

	t.Run("default MaxSessionDuration", func(t *testing.T) {
		createRole(t, c, "Plain", trust)
		requireEqual(t, aws.ToInt32(getRole(t, c, "Plain").MaxSessionDuration),
			defaultMaxSession, "MaxSessionDuration")
		requireEqual(t, aws.ToString(getRole(t, c, "Plain").Path), "/", "Path")
	})
}

func roleNames(roles []types.Role) []string {
	names := make([]string, 0, len(roles))
	for _, r := range roles {
		names = append(names, aws.ToString(r.RoleName))
	}
	return names
}

func TestInvalidRoleInput(t *testing.T) {
	// CreateRole: RoleName 1 to 64 of [\w+=,.@-]; MaxSessionDuration 3600 to
	// 43200; Path "/" or /[!-~]+/; ValidationError for each (Common Error
	// Types). Names are unique without regard to case, EntityAlreadyExists.
	_, c := rootIAM(t)
	trust := aws.String(trustDoc(rootARN(defaultAccountID)))
	createRole(t, c, "Taken", *trust)

	invalid := map[string]iam.CreateRoleInput{
		"name with space": {RoleName: aws.String("a b"), AssumeRolePolicyDocument: trust},
		"name of 65": {
			RoleName: aws.String(strings.Repeat("r", 65)), AssumeRolePolicyDocument: trust,
		},
		"MaxSessionDuration 3599": {
			RoleName: aws.String("r1"), AssumeRolePolicyDocument: trust,
			MaxSessionDuration: aws.Int32(3599),
		},
		"MaxSessionDuration 43201": {
			RoleName: aws.String("r2"), AssumeRolePolicyDocument: trust,
			MaxSessionDuration: aws.Int32(43201),
		},
		"path without slashes": {
			RoleName: aws.String("r3"), AssumeRolePolicyDocument: trust, Path: aws.String("x"),
		},
	}
	for name, in := range invalid {
		t.Run(name, func(t *testing.T) {
			requireCode(t, errOf(c.CreateRole(t.Context(), &in)), codeValidation)
		})
	}

	t.Run("name in another case", func(t *testing.T) {
		err := errOf(c.CreateRole(t.Context(), &iam.CreateRoleInput{
			RoleName: aws.String("taken"), AssumeRolePolicyDocument: trust,
		}))
		requireAs[*types.EntityAlreadyExistsException](t, err)
	})

	t.Run("longest name", func(t *testing.T) {
		createRole(t, c, strings.Repeat("r", 64), *trust)
	})
}

func TestUpdateRole(t *testing.T) {
	_, c := rootIAM(t)
	createRole(t, c, "Worker", trustDoc(rootARN(defaultAccountID)))

	// UpdateRole "Updates the description or maximum session duration
	// setting of a role."
	_, err := c.UpdateRole(t.Context(), &iam.UpdateRoleInput{
		RoleName: aws.String("Worker"), Description: aws.String("new"),
		MaxSessionDuration: aws.Int32(43200),
	})
	requireNoErr(t, err, "update role")
	got := getRole(t, c, "Worker")
	requireEqual(t, aws.ToString(got.Description), "new", "Description")
	requireEqual(t, aws.ToInt32(got.MaxSessionDuration), 43200, "MaxSessionDuration")

	t.Run("MaxSessionDuration out of range", func(t *testing.T) {
		err := errOf(c.UpdateRole(t.Context(), &iam.UpdateRoleInput{
			RoleName: aws.String("Worker"), MaxSessionDuration: aws.Int32(3599),
		}))
		requireCode(t, err, codeValidation)
	})

	t.Run("unknown role", func(t *testing.T) {
		err := errOf(c.UpdateRole(t.Context(), &iam.UpdateRoleInput{
			RoleName: aws.String("nobody"), Description: aws.String("x"),
		}))
		requireAs[*types.NoSuchEntityException](t, err)
	})
}

func TestUpdateAssumeRolePolicy(t *testing.T) {
	_, c := rootIAM(t)
	createRole(t, c, "Worker", trustDoc(rootARN(defaultAccountID)))
	createUser(t, c, "dev")
	next := trustDoc(userARN(defaultAccountID, "/", "dev"))

	_, err := c.UpdateAssumeRolePolicy(t.Context(), &iam.UpdateAssumeRolePolicyInput{
		RoleName: aws.String("Worker"), PolicyDocument: aws.String(next),
	})
	requireNoErr(t, err, "update assume role policy")
	requireSameDoc(t, getRole(t, c, "Worker").AssumeRolePolicyDocument, next,
		"AssumeRolePolicyDocument")

	// MalformedPolicyDocument and NoSuchEntity are in its errors.
	t.Run("malformed", func(t *testing.T) {
		err := errOf(c.UpdateAssumeRolePolicy(t.Context(), &iam.UpdateAssumeRolePolicyInput{
			RoleName: aws.String("Worker"), PolicyDocument: aws.String("{not json"),
		}))
		requireAs[*types.MalformedPolicyDocumentException](t, err)
		requireSameDoc(t, getRole(t, c, "Worker").AssumeRolePolicyDocument, next,
			"AssumeRolePolicyDocument after the refused update")
	})
	t.Run("unknown role", func(t *testing.T) {
		err := errOf(c.UpdateAssumeRolePolicy(t.Context(), &iam.UpdateAssumeRolePolicyInput{
			RoleName: aws.String("nobody"), PolicyDocument: aws.String(next),
		}))
		requireAs[*types.NoSuchEntityException](t, err)
	})
}

func TestRolePolicies(t *testing.T) {
	_, c := rootIAM(t)
	createRole(t, c, "Worker", trustDoc(rootARN(defaultAccountID)))
	mine := createPolicy(t, c, "Mine", policyDoc(allow("iam:GetUser", "*")))
	doc := policyDoc(allow("iam:ListUsers", "*"))

	attachRolePolicy(t, c, "Worker", mine)
	attachRolePolicy(t, c, "Worker", adminAccessARN)
	got := attachedARNs(attachedRolePolicies(t, c, "Worker"))
	if len(got) != 2 || got["Mine"] != mine || got["AdministratorAccess"] != adminAccessARN {
		t.Fatalf("attached role policies: %v", got)
	}
	detachRolePolicy(t, c, "Worker", adminAccessARN)
	requireEqual(t, len(attachedRolePolicies(t, c, "Worker")), 1, "attached after detach")

	putRolePolicy(t, c, "Worker", "Lister", doc)
	requireSameNames(t, rolePolicyNames(t, c, "Worker"), []string{"Lister"})
	out, err := c.GetRolePolicy(t.Context(), &iam.GetRolePolicyInput{
		RoleName: aws.String("Worker"), PolicyName: aws.String("Lister"),
	})
	requireNoErr(t, err, "get role policy")
	requireEqual(t, aws.ToString(out.RoleName), "Worker", "RoleName")
	requireEqual(t, aws.ToString(out.PolicyName), "Lister", "PolicyName")
	requireSameDoc(t, out.PolicyDocument, doc, "PolicyDocument")

	_, err = c.DeleteRolePolicy(t.Context(), &iam.DeleteRolePolicyInput{
		RoleName: aws.String("Worker"), PolicyName: aws.String("Lister"),
	})
	requireNoErr(t, err, "delete role policy")
	requireEqual(t, len(rolePolicyNames(t, c, "Worker")), 0, "inline after delete")
	requireAs[*types.NoSuchEntityException](t, errOf(c.GetRolePolicy(t.Context(),
		&iam.GetRolePolicyInput{RoleName: aws.String("Worker"), PolicyName: aws.String("Lister")})))

	t.Run("unknown role", func(t *testing.T) {
		requireAs[*types.NoSuchEntityException](t, errOf(c.AttachRolePolicy(t.Context(),
			&iam.AttachRolePolicyInput{
				RoleName: aws.String("nobody"), PolicyArn: aws.String(mine),
			})))
		requireAs[*types.NoSuchEntityException](t, errOf(c.PutRolePolicy(t.Context(),
			&iam.PutRolePolicyInput{
				RoleName: aws.String("nobody"), PolicyName: aws.String("p"),
				PolicyDocument: aws.String(doc),
			})))
	})
}

func TestDeleteRole(t *testing.T) {
	// DeleteRole: remove the role's "Inline policies (DeleteRolePolicy)" and
	// "Attached managed policies (DetachRolePolicy)" first, "or the deletion
	// fails"; DeleteConflict is in its errors.
	_, c := rootIAM(t)
	createRole(t, c, "Doomed", trustDoc(rootARN(defaultAccountID)))
	deleteRole := func() error {
		return errOf(c.DeleteRole(t.Context(), &iam.DeleteRoleInput{
			RoleName: aws.String("Doomed"),
		}))
	}

	attachRolePolicy(t, c, "Doomed", adminAccessARN)
	t.Run("with an attached policy", func(t *testing.T) {
		requireAs[*types.DeleteConflictException](t, deleteRole())
		getRole(t, c, "Doomed")
	})
	detachRolePolicy(t, c, "Doomed", adminAccessARN)

	putRolePolicy(t, c, "Doomed", "inline", policyDoc(allow("iam:GetUser", "*")))
	t.Run("with an inline policy", func(t *testing.T) {
		requireAs[*types.DeleteConflictException](t, deleteRole())
	})
	_, err := c.DeleteRolePolicy(t.Context(), &iam.DeleteRolePolicyInput{
		RoleName: aws.String("Doomed"), PolicyName: aws.String("inline"),
	})
	requireNoErr(t, err, "delete the inline policy")

	requireNoErr(t, deleteRole(), "delete the role once its policies are gone")
	requireAs[*types.NoSuchEntityException](t, errOf(c.GetRole(t.Context(),
		&iam.GetRoleInput{RoleName: aws.String("Doomed")})))
	requireAs[*types.NoSuchEntityException](t, deleteRole())

	t.Run("name is free again", func(t *testing.T) {
		createRole(t, c, "Doomed", trustDoc(rootARN(defaultAccountID)))
	})
}
