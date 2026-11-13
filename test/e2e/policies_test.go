//go:build e2e

package e2e

import (
	"encoding/json"
	"fmt"
	"net/url"
	"reflect"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/iam/types"
)

// policyVersion is the policy language version that supports policy
// variables (IAM User Guide, IAM JSON policy elements: Version).
const policyVersion = "2012-10-17"

// adminAccessARN is the AWS managed AdministratorAccess policy; AWS managed
// policies live in the "aws" account (AttachUserPolicy's sample request).
const adminAccessARN = "arn:aws:iam::aws:policy/AdministratorAccess"

// adminAccessDoc is the document AWS publishes for AdministratorAccess.
const adminAccessDoc = `{"Version":"2012-10-17","Statement":[` +
	`{"Effect":"Allow","Action":"*","Resource":"*"}]}`

// policyIDPattern: managed policy IDs begin with ANPA (IAM and STS quotas,
// "Unique IDs created by IAM").
var policyIDPattern = regexp.MustCompile(`^ANPA[A-Z0-9]+$`)

// statement is one statement of a policy document (IAM JSON policy
// reference, Grammar).
type statement struct {
	Action    any    `json:"Action,omitempty"`
	Resource  any    `json:"Resource,omitempty"`
	Principal any    `json:"Principal,omitempty"`
	Effect    string `json:"Effect"`
}

func allow(action, resource any) statement {
	return statement{Effect: "Allow", Action: action, Resource: resource}
}

// deny denies action on every resource.
func deny(action any) statement {
	return statement{Effect: "Deny", Action: action, Resource: "*"}
}

// policyDoc is a policy document holding stmts.
func policyDoc(stmts ...statement) string {
	b, _ := json.Marshal(map[string]any{"Version": policyVersion, "Statement": stmts})
	return string(b)
}

// trustDoc is a role trust policy letting the AWS principals call
// sts:AssumeRole (Principal element, AWS account and IAM user principals).
func trustDoc(principals ...string) string {
	return policyDoc(statement{
		Effect:    "Allow",
		Action:    "sts:AssumeRole",
		Principal: map[string]any{"AWS": principals},
	})
}

// policyARN is a customer managed policy's ARN in the default account:
// arn:aws:iam::<account>:policy/<path><name> (service authorization
// reference, IAM resource type "policy").
func policyARN(path, name string) string {
	return "arn:aws:iam::" + defaultAccountID + ":policy" + path + name
}

// decodeDoc parses a policy document IAM returned. GetPolicyVersion,
// GetUserPolicy, GetRolePolicy and the Role's AssumeRolePolicyDocument are
// "URL-encoded compliant with RFC 3986" (PolicyVersion.Document), and the Go
// SDK does not decode them. PathUnescape leaves a '+' as it is, as RFC 3986
// encoding does not use it for a space.
func decodeDoc(t *testing.T, doc *string, what string) any {
	t.Helper()
	if doc == nil {
		t.Fatalf("%s: no document", what)
	}
	plain, err := url.PathUnescape(aws.ToString(doc))
	requireNoErr(t, err, what+": URL-decode")
	var v any
	requireNoErr(t, json.Unmarshal([]byte(plain), &v), what+": parse "+plain)
	return v
}

// requireSameDoc fails unless the returned document is want as JSON. The
// reference does not promise to return the document byte for byte, so the
// comparison is of the parsed values.
func requireSameDoc(t *testing.T, got *string, want, what string) {
	t.Helper()
	var w any
	requireNoErr(t, json.Unmarshal([]byte(want), &w), what+": parse the expected document")
	if g := decodeDoc(t, got, what); !reflect.DeepEqual(g, w) {
		t.Fatalf("%s: got %v, want %v", what, g, w)
	}
}

// createPolicy creates a customer managed policy at the default path and
// returns its ARN.
func createPolicy(t *testing.T, c *iam.Client, name, doc string) string {
	t.Helper()
	out, err := c.CreatePolicy(t.Context(), &iam.CreatePolicyInput{
		PolicyName: aws.String(name), PolicyDocument: aws.String(doc),
	})
	requireNoErr(t, err, "create policy "+name)
	return aws.ToString(out.Policy.Arn)
}

func getPolicy(t *testing.T, c *iam.Client, arn string) *types.Policy {
	t.Helper()
	out, err := c.GetPolicy(t.Context(), &iam.GetPolicyInput{PolicyArn: aws.String(arn)})
	requireNoErr(t, err, "get policy "+arn)
	if out.Policy == nil {
		t.Fatalf("get policy %s returned no policy", arn)
	}
	return out.Policy
}

func createVersion(t *testing.T, c *iam.Client, arn, doc string, def bool) string {
	t.Helper()
	out, err := c.CreatePolicyVersion(t.Context(), &iam.CreatePolicyVersionInput{
		PolicyArn: aws.String(arn), PolicyDocument: aws.String(doc), SetAsDefault: def,
	})
	requireNoErr(t, err, "create policy version")
	return aws.ToString(out.PolicyVersion.VersionId)
}

func listVersions(t *testing.T, c *iam.Client, arn string) []types.PolicyVersion {
	t.Helper()
	out, err := c.ListPolicyVersions(t.Context(), &iam.ListPolicyVersionsInput{
		PolicyArn: aws.String(arn),
	})
	requireNoErr(t, err, "list policy versions")
	return out.Versions
}

// defaultVersion returns the ID of the one version marked default, failing
// unless exactly one is.
func defaultVersion(t *testing.T, versions []types.PolicyVersion) string {
	t.Helper()
	var ids []string
	for _, v := range versions {
		if v.IsDefaultVersion {
			ids = append(ids, aws.ToString(v.VersionId))
		}
	}
	if len(ids) != 1 {
		t.Fatalf("default versions: %v, want exactly one", ids)
	}
	return ids[0]
}

func versionIDs(versions []types.PolicyVersion) []string {
	ids := make([]string, 0, len(versions))
	for _, v := range versions {
		ids = append(ids, aws.ToString(v.VersionId))
	}
	return ids
}

func policyNames(policies []types.Policy) []string {
	names := make([]string, 0, len(policies))
	for _, p := range policies {
		names = append(names, aws.ToString(p.PolicyName))
	}
	return names
}

func listPolicies(t *testing.T, c *iam.Client, in *iam.ListPoliciesInput) []string {
	t.Helper()
	var names []string
	p := iam.NewListPoliciesPaginator(c, in)
	for p.HasMorePages() {
		page, err := p.NextPage(t.Context())
		requireNoErr(t, err, "list policies")
		names = append(names, policyNames(page.Policies)...)
	}
	return names
}

func TestCreatePolicy(t *testing.T) {
	_, c := rootIAM(t)
	doc := policyDoc(allow("iam:GetUser", "*"))
	before := time.Now()

	out, err := c.CreatePolicy(t.Context(), &iam.CreatePolicyInput{
		PolicyName:     aws.String("ReadUsers"),
		PolicyDocument: aws.String(doc),
		Path:           aws.String("/team/"),
		Description:    aws.String("Reads users"),
	})
	requireNoErr(t, err, "create policy")
	p := out.Policy
	arn := policyARN("/team/", "ReadUsers")
	requirePolicy(t, p, arn, "/team/", "ReadUsers")
	// CreatePolicy "creates a policy version with a version identifier of
	// v1 and sets v1 as the policy's default version".
	requireEqual(t, aws.ToString(p.DefaultVersionId), "v1", "DefaultVersionId")
	requireEqual(t, aws.ToInt32(p.AttachmentCount), 0, "AttachmentCount")
	requireRecent(t, p.CreateDate, before, time.Now(), "CreateDate")

	t.Run("GetPolicy agrees", func(t *testing.T) {
		got := getPolicy(t, c, arn)
		requirePolicy(t, got, arn, "/team/", "ReadUsers")
		requireEqual(t, aws.ToString(got.PolicyId), aws.ToString(p.PolicyId), "PolicyId")
		// Policy.Description "is included in the response to the GetPolicy
		// operation".
		requireEqual(t, aws.ToString(got.Description), "Reads users", "Description")
		requireEqual(t, aws.ToString(got.DefaultVersionId), "v1", "DefaultVersionId")
	})

	t.Run("GetPolicyVersion v1", func(t *testing.T) {
		v, err := c.GetPolicyVersion(t.Context(), &iam.GetPolicyVersionInput{
			PolicyArn: aws.String(arn), VersionId: aws.String("v1"),
		})
		requireNoErr(t, err, "get policy version")
		requireEqual(t, aws.ToString(v.PolicyVersion.VersionId), "v1", "VersionId")
		requireEqual(t, v.PolicyVersion.IsDefaultVersion, true, "IsDefaultVersion")
		requireSameDoc(t, v.PolicyVersion.Document, doc, "Document")
	})

	t.Run("ListPolicies Local", func(t *testing.T) {
		got := listPolicies(t, c, &iam.ListPoliciesInput{Scope: types.PolicyScopeTypeLocal})
		requireSameNames(t, got, []string{"ReadUsers"})
	})
}

// requirePolicy checks the fields every Policy carries.
func requirePolicy(t *testing.T, p *types.Policy, arn, path, name string) {
	t.Helper()
	if p == nil {
		t.Fatal("no policy returned")
	}
	requireEqual(t, aws.ToString(p.PolicyName), name, "PolicyName")
	requireEqual(t, aws.ToString(p.Path), path, "Path")
	requireEqual(t, aws.ToString(p.Arn), arn, "Arn")
	requireMatch(t, policyIDPattern, aws.ToString(p.PolicyId), "PolicyId")
	requireEqual(t, p.IsAttachable, true, "IsAttachable")
}

func TestAdministratorAccessPolicy(t *testing.T) {
	// The design ships AdministratorAccess, the document AWS publishes, as an
	// AWS managed policy in every account.
	_, c := rootIAM(t)
	p := getPolicy(t, c, adminAccessARN)
	requireEqual(t, aws.ToString(p.PolicyName), "AdministratorAccess", "PolicyName")
	requireEqual(t, aws.ToString(p.Path), "/", "Path")
	requireEqual(t, p.IsAttachable, true, "IsAttachable")

	v, err := c.GetPolicyVersion(t.Context(), &iam.GetPolicyVersionInput{
		PolicyArn: aws.String(adminAccessARN), VersionId: p.DefaultVersionId,
	})
	requireNoErr(t, err, "get the default version of AdministratorAccess")
	requireSameDoc(t, v.PolicyVersion.Document, adminAccessDoc, "Document")
}

func TestListPoliciesFilters(t *testing.T) {
	_, c := rootIAM(t)
	for name, path := range map[string]string{"InX": "/x/", "AtRoot": "/"} {
		_, err := c.CreatePolicy(t.Context(), &iam.CreatePolicyInput{
			PolicyName:     aws.String(name),
			PolicyDocument: aws.String(policyDoc(allow("iam:GetUser", "*"))),
			Path:           aws.String(path),
		})
		requireNoErr(t, err, "create policy "+name)
	}
	createUser(t, c, "dev")

	// ListPoliciesInput: Scope Local is the account's own, AWS the AWS
	// managed ones, All (the default) both; PathPrefix filters by path;
	// OnlyAttached lists only policies attached to a user, group or role.
	local := types.PolicyScopeTypeLocal
	tests := []struct {
		in   iam.ListPoliciesInput
		name string
		want []string
	}{
		{iam.ListPoliciesInput{Scope: local}, "Local", []string{"InX", "AtRoot"}},
		{
			iam.ListPoliciesInput{Scope: local, PathPrefix: aws.String("/x/")},
			"PathPrefix",
			[]string{"InX"},
		},
		{iam.ListPoliciesInput{Scope: local, OnlyAttached: true}, "OnlyAttached", nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			requireSameNames(t, listPolicies(t, c, &tt.in), tt.want)
		})
	}

	t.Run("AWS and All include AdministratorAccess", func(t *testing.T) {
		requireContains(t, listPolicies(t, c, &iam.ListPoliciesInput{
			Scope: types.PolicyScopeTypeAws,
		}), "AdministratorAccess")
		all := listPolicies(t, c, &iam.ListPoliciesInput{})
		for _, n := range []string{"InX", "AtRoot", "AdministratorAccess"} {
			requireContains(t, all, n)
		}
	})

	t.Run("OnlyAttached after attaching", func(t *testing.T) {
		attachUserPolicy(t, c, "dev", policyARN("/", "AtRoot"))
		attachUserPolicy(t, c, "dev", adminAccessARN)
		requireSameNames(t, listPolicies(t, c, &iam.ListPoliciesInput{OnlyAttached: true}),
			[]string{"AtRoot", "AdministratorAccess"})
	})
}

func requireContains(t *testing.T, got []string, want string) {
	t.Helper()
	for _, g := range got {
		if g == want {
			return
		}
	}
	t.Fatalf("%v does not contain %q", got, want)
}

func TestListPoliciesPaginator(t *testing.T) {
	_, c := rootIAM(t)
	want := make([]string, 0, 3)
	for i := range 3 {
		name := fmt.Sprintf("policy%d", i)
		createPolicy(t, c, name, policyDoc(allow("iam:GetUser", "*")))
		want = append(want, name)
	}
	p := iam.NewListPoliciesPaginator(c, &iam.ListPoliciesInput{Scope: types.PolicyScopeTypeLocal},
		func(o *iam.ListPoliciesPaginatorOptions) { o.Limit = 1 })
	got := walkPages(t, 1, p.HasMorePages, p.NextPage,
		func(o *iam.ListPoliciesOutput) []string { return policyNames(o.Policies) })
	requireSameNames(t, got, want)
}

func TestDuplicatePolicy(t *testing.T) {
	// CreatePolicyInput.PolicyName: names are unique within the account and
	// "not distinguished by case"; EntityAlreadyExists is in its errors.
	_, c := rootIAM(t)
	doc := policyDoc(allow("iam:GetUser", "*"))
	createPolicy(t, c, "Shared", doc)
	for _, name := range []string{"Shared", "shared"} {
		t.Run(name, func(t *testing.T) {
			err := errOf(c.CreatePolicy(t.Context(), &iam.CreatePolicyInput{
				PolicyName: aws.String(name), PolicyDocument: aws.String(doc),
			}))
			requireAs[*types.EntityAlreadyExistsException](t, err)
		})
	}
}

func TestInvalidPolicyInput(t *testing.T) {
	// CreatePolicy: PolicyName 1 to 128 of [\w+=,.@-]; Path 1 to 512 matching
	// ((/[A-Za-z0-9\.,\+@=_-]+)*)/; Description at most 1000; PolicyDocument
	// at least 1. Constraint failures are ValidationError (Common Error
	// Types).
	_, c := rootIAM(t)
	doc := aws.String(policyDoc(allow("iam:GetUser", "*")))
	tests := map[string]iam.CreatePolicyInput{
		"empty name":      {PolicyName: aws.String(""), PolicyDocument: doc},
		"name with space": {PolicyName: aws.String("a b"), PolicyDocument: doc},
		"name of 129":     {PolicyName: aws.String(strings.Repeat("n", 129)), PolicyDocument: doc},
		"path without slashes": {
			PolicyName: aws.String("p1"), PolicyDocument: doc, Path: aws.String("x"),
		},
		"path with a star": {
			PolicyName: aws.String("p2"), PolicyDocument: doc, Path: aws.String("/a*/"),
		},
		"description of 1001": {
			PolicyName: aws.String("p3"), PolicyDocument: doc,
			Description: aws.String(strings.Repeat("d", 1001)),
		},
		"empty document": {PolicyName: aws.String("p4"), PolicyDocument: aws.String("")},
	}
	for name, in := range tests {
		t.Run(name, func(t *testing.T) {
			requireCode(t, errOf(c.CreatePolicy(t.Context(), &in)), codeValidation)
		})
	}
	requireSameNames(t, listPolicies(t, c, &iam.ListPoliciesInput{
		Scope: types.PolicyScopeTypeLocal,
	}), nil)
}

func TestUnknownPolicy(t *testing.T) {
	// NoSuchEntity is in the errors of each operation below.
	_, c := rootIAM(t)
	createUser(t, c, "dev")
	arn := aws.String(policyARN("/", "Nope"))
	doc := aws.String(policyDoc(allow("iam:GetUser", "*")))

	calls := map[string]func() error{
		"GetPolicy": func() error {
			return errOf(c.GetPolicy(t.Context(), &iam.GetPolicyInput{PolicyArn: arn}))
		},
		"DeletePolicy": func() error {
			return errOf(c.DeletePolicy(t.Context(), &iam.DeletePolicyInput{PolicyArn: arn}))
		},
		"GetPolicyVersion": func() error {
			return errOf(c.GetPolicyVersion(t.Context(), &iam.GetPolicyVersionInput{
				PolicyArn: arn, VersionId: aws.String("v1"),
			}))
		},
		"ListPolicyVersions": func() error {
			return errOf(c.ListPolicyVersions(t.Context(),
				&iam.ListPolicyVersionsInput{PolicyArn: arn}))
		},
		"CreatePolicyVersion": func() error {
			return errOf(c.CreatePolicyVersion(t.Context(), &iam.CreatePolicyVersionInput{
				PolicyArn: arn, PolicyDocument: doc,
			}))
		},
		"AttachUserPolicy": func() error {
			return errOf(c.AttachUserPolicy(t.Context(), &iam.AttachUserPolicyInput{
				PolicyArn: arn, UserName: aws.String("dev"),
			}))
		},
	}
	for name, call := range calls {
		t.Run(name, func(t *testing.T) {
			requireAs[*types.NoSuchEntityException](t, call())
		})
	}
}
