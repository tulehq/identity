package keysource_test

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"tule.dev/sigv4"

	"tule.dev/identity/keysource"
	"tule.dev/identity/servicerole"
)

// attributes is the part of a principal the endpoint reports at
// keysource.VersionAttributes.
type attributes struct {
	Tags         map[string]string
	ARN          string
	PrincipalARN string
	UserID       string
	Type         sigv4.PrincipalType
}

func attributesOf(p sigv4.Principal) attributes {
	return attributes{
		Tags: p.Tags, ARN: p.ARN, PrincipalARN: p.PrincipalARN, UserID: p.UserID, Type: p.Type,
	}
}

func signingPrincipal(t *testing.T, c *keysource.Client, keyID, token string) sigv4.Principal {
	t.Helper()
	got, err := c.SigningKey(t.Context(), scope(keyID, token))
	if err != nil {
		t.Fatalf("signing key of %s: %v", keyID, err)
	}
	return got.Principal
}

func requireAttributes(t *testing.T, got sigv4.Principal, want attributes) {
	t.Helper()
	if a := attributesOf(got); !reflect.DeepEqual(a, want) {
		t.Fatalf("attributes = %+v, want %+v", a, want)
	}
}

// tagsOf is the tags of key and value pairs.
func tagsOf(kv ...[2]string) []iamtypes.Tag {
	out := make([]iamtypes.Tag, 0, len(kv))
	for _, t := range kv {
		out = append(out, iamtypes.Tag{Key: aws.String(t[0]), Value: aws.String(t[1])})
	}
	return out
}

func TestTheClientReportsTheRootUsersAttributes(t *testing.T) {
	url := startIdentity(t)
	c := newClient(t, url, rootKeyID, rootSecret)
	requireAttributes(t, signingPrincipal(t, c, rootKeyID, ""), attributes{
		ARN:          "arn:aws:iam::000000000000:root",
		PrincipalARN: "arn:aws:iam::000000000000:root",
		UserID:       "000000000000",
		Type:         sigv4.PrincipalTypeAccount,
	})
}

func TestTheClientReportsAUsersAttributes(t *testing.T) {
	url := startIdentity(t)
	root := iamRoot(url)
	out, err := root.CreateUser(t.Context(), &iam.CreateUserInput{
		UserName: aws.String("builder"), Path: aws.String("/eng/ci/"),
		Tags: tagsOf([2]string{"Team", "blue"}, [2]string{"env", "dev"}),
	})
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	key, err := root.CreateAccessKey(t.Context(), &iam.CreateAccessKeyInput{
		UserName: aws.String("builder"),
	})
	if err != nil {
		t.Fatalf("create access key: %v", err)
	}
	c := newClient(t, url, rootKeyID, rootSecret)
	keyID := aws.ToString(key.AccessKey.AccessKeyId)
	userARN := "arn:aws:iam::000000000000:user/eng/ci/builder"
	want := attributes{
		ARN: userARN, PrincipalARN: userARN, UserID: aws.ToString(out.User.UserId),
		Type: sigv4.PrincipalTypeUser,
		// Keys keep the case they were set with.
		Tags: map[string]string{"Team": "blue", "env": "dev"},
	}
	requireAttributes(t, signingPrincipal(t, c, keyID, ""), want)

	// A tag set again with its key in another case replaces it, key and value.
	if _, err = root.TagUser(t.Context(), &iam.TagUserInput{
		UserName: aws.String("builder"), Tags: tagsOf([2]string{"team", "red"}),
	}); err != nil {
		t.Fatalf("tag user: %v", err)
	}
	want.Tags = map[string]string{"team": "red", "env": "dev"}
	requireAttributes(t, signingPrincipal(t, c, keyID, ""), want)
}

// trustUser is a trust policy that lets the IAM user assume the role.
func trustUser(arn string) string {
	return `{"Version":"2012-10-17","Statement":[{"Effect":"Allow",` +
		`"Principal":{"AWS":"` + arn + `"},"Action":"sts:AssumeRole"}]}`
}

// A role session's PrincipalArn is its role's ARN with the role's path,
// which its own assumed-role ARN leaves out; its UserId is the role's ID
// and the session's name; and its tags are the role's.
func TestTheClientReportsARoleSessionsAttributes(t *testing.T) {
	url := startIdentity(t)
	root := iamRoot(url)
	key := userKey(t, url)
	role, err := root.CreateRole(t.Context(), &iam.CreateRoleInput{
		RoleName: aws.String("deployer"), Path: aws.String("/app/prod/"),
		AssumeRolePolicyDocument: aws.String(trustUser("arn:aws:iam::000000000000:user/dev")),
		Tags:                     tagsOf([2]string{"Project", "pegasus"}),
	})
	if err != nil {
		t.Fatalf("create role: %v", err)
	}
	user := sts.New(sts.Options{
		Region: "us-east-1", BaseEndpoint: aws.String(url), RetryMaxAttempts: 1,
		Credentials: credentials.NewStaticCredentialsProvider(
			aws.ToString(key.AccessKeyId), aws.ToString(key.SecretAccessKey), ""),
	})
	session, err := user.AssumeRole(t.Context(), &sts.AssumeRoleInput{
		RoleArn:         role.Role.Arn,
		RoleSessionName: aws.String("release-42"),
	})
	if err != nil {
		t.Fatalf("assume role: %v", err)
	}
	c := newClient(t, url, rootKeyID, rootSecret)
	keyID := aws.ToString(session.Credentials.AccessKeyId)
	token := aws.ToString(session.Credentials.SessionToken)
	roleID := aws.ToString(role.Role.RoleId)
	requireAttributes(t, signingPrincipal(t, c, keyID, token), attributes{
		ARN:          "arn:aws:sts::000000000000:assumed-role/deployer/release-42",
		PrincipalARN: "arn:aws:iam::000000000000:role/app/prod/deployer",
		UserID:       roleID + ":release-42",
		Type:         sigv4.PrincipalTypeAssumedRole,
		Tags:         map[string]string{"Project": "pegasus"},
	})

	// Once its role is deleted, the session has no role: no PrincipalArn and
	// no tags, though it still names the role's ID.
	if _, err = root.DeleteRole(t.Context(), &iam.DeleteRoleInput{
		RoleName: aws.String("deployer"),
	}); err != nil {
		t.Fatalf("delete role: %v", err)
	}
	requireAttributes(t, signingPrincipal(t, c, keyID, token), attributes{
		ARN:    "arn:aws:sts::000000000000:assumed-role/deployer/release-42",
		UserID: roleID + ":release-42",
		Type:   sigv4.PrincipalTypeAssumedRole,
	})
}

// A session from the assume-role endpoint, as a Tule service takes on a
// role as an AWS service principal, is a role session like any other.
func TestTheClientReportsAServiceRoleSessionsAttributes(t *testing.T) {
	url := startIdentity(t)
	role, err := iamRoot(url).CreateRole(t.Context(), &iam.CreateRoleInput{
		RoleName: aws.String("fn"), Path: aws.String("/service-role/"),
		AssumeRolePolicyDocument: aws.String(`{"Version":"2012-10-17","Statement":[` +
			`{"Effect":"Allow","Principal":{"Service":"lambda.amazonaws.com"},` +
			`"Action":"sts:AssumeRole"}]}`),
		Tags: tagsOf([2]string{"function", "resize"}),
	})
	if err != nil {
		t.Fatalf("create role: %v", err)
	}
	roles, err := servicerole.New(servicerole.Config{
		Endpoint: url, AccessKeyID: rootKeyID, SecretAccessKey: rootSecret,
	})
	if err != nil {
		t.Fatalf("new servicerole client: %v", err)
	}
	session, err := roles.AssumeServiceRole(t.Context(), aws.ToString(role.Role.Arn),
		"invocation", "lambda.amazonaws.com", 15*time.Minute)
	if err != nil {
		t.Fatalf("assume service role: %v", err)
	}
	c := newClient(t, url, rootKeyID, rootSecret)
	requireAttributes(t, signingPrincipal(t, c, session.Credentials.AccessKeyID,
		session.Credentials.SessionToken), attributes{
		ARN:          "arn:aws:sts::000000000000:assumed-role/fn/invocation",
		PrincipalARN: "arn:aws:iam::000000000000:role/service-role/fn",
		UserID:       aws.ToString(role.Role.RoleId) + ":invocation",
		Type:         sigv4.PrincipalTypeAssumedRole,
		Tags:         map[string]string{"function": "resize"},
	})
}

// answering serves a version 4 answer whose principal is principal, JSON
// for its fields besides AccountId, Arn and AccessKeyId.
func answering(t *testing.T, principal string) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"Version":4,"SigningKey":"AA==","Principal":{` +
			`"AccountId":"000000000000","Arn":"arn:aws:iam::000000000000:user/dev",` +
			`"AccessKeyId":"AKIAAAAAAAAAAAAAAAAA"` + principal + `}}`))
	}))
	t.Cleanup(srv.Close)
	return srv.URL
}

// tagsJSON is a JSON object of n tags, k0 to k<n-1>.
func tagsJSON(n int) string {
	tags := make([]string, 0, n)
	for i := range n {
		tags = append(tags, fmt.Sprintf(`"k%d":"v"`, i))
	}
	return "{" + strings.Join(tags, ",") + "}"
}

// The client refuses a principal that breaks the endpoint's contract,
// rather than hand a verifier one a policy evaluator would misread.
func TestTheClientRefusesAnInvalidPrincipal(t *testing.T) {
	for name, principal := range map[string]string{
		"unknown type":       `,"PrincipalType":"Admin"`,
		"no type":            ``,
		"a root user":        `,"PrincipalType":"User","Root":true`,
		"an account no root": `,"PrincipalType":"Account"`,
		"too many tags":      `,"PrincipalType":"User","Tags":` + tagsJSON(keysource.MaxTags+1),
		"keys in two cases":  `,"PrincipalType":"User","Tags":{"Env":"1","env":"2"}`,
		"keys folded":        `,"PrincipalType":"User","Tags":{"Ä":"1","ä":"2"}`,
		"unknown, yet an ID": `,"PrincipalType":"User","OrgUnknown":true,"OrgId":"` + orgID + `",` +
			`"OrgPaths":["` + orgID + `/r-ab12/"]`,
		"unknown, yet a path": `,"PrincipalType":"User","OrgUnknown":true,` +
			`"OrgPaths":["` + orgID + `/r-ab12/"]`,
		"a path, no ID":   `,"PrincipalType":"User","OrgPaths":["` + orgID + `/r-ab12/"]`,
		"an ID, no path":  `,"PrincipalType":"User","OrgId":"` + orgID + `"`,
		"not an org ID":   `,"PrincipalType":"User","OrgId":"o-short","OrgPaths":["o-short/r-ab12/"]`,
		"two paths":       `,"PrincipalType":"User","OrgId":"` + orgID + `","OrgPaths":["` + orgID + `/r-ab12/","` + orgID + `/r-ab12/ou-ab12-11111111/"]`,
		"another org":     `,"PrincipalType":"User","OrgId":"` + orgID + `","OrgPaths":["o-zzzzzzzzzz/r-ab12/"]`,
		"no root":         `,"PrincipalType":"User","OrgId":"` + orgID + `","OrgPaths":["` + orgID + `/ou-ab12-11111111/"]`,
		"no final slash":  `,"PrincipalType":"User","OrgId":"` + orgID + `","OrgPaths":["` + orgID + `/r-ab12"]`,
		"a wildcard path": `,"PrincipalType":"User","OrgId":"` + orgID + `","OrgPaths":["` + orgID + `/*"]`,
	} {
		t.Run(name, func(t *testing.T) {
			_, err := newClient(t, answering(t, principal), rootKeyID, rootSecret).SigningKey(
				t.Context(), scope("AKIAAAAAAAAAAAAAAAAA", ""))
			var e *keysource.Error
			if !errors.As(err, &e) || e.Code != keysource.CodeInvalidResponse {
				t.Fatalf("got %v, want a %s *keysource.Error", err, keysource.CodeInvalidResponse)
			}
		})
	}

	// At the limit, with keys distinct regardless of case, it is accepted.
	got, err := newClient(t, answering(t, `,"PrincipalType":"User","Tags":`+
		tagsJSON(keysource.MaxTags)),
		rootKeyID, rootSecret).SigningKey(t.Context(), scope("AKIAAAAAAAAAAAAAAAAA", ""))
	if err != nil || len(got.Principal.Tags) != keysource.MaxTags {
		t.Fatalf("50 tags: %d tags, %v", len(got.Principal.Tags), err)
	}
}

// orgID is the IAM User Guide's example organization ID
// (aws:PrincipalOrgPaths).
const orgID = "o-a1b2c3d4e5"

// The client fills the organization keys the endpoint reports.
func TestTheClientReportsTheOrganizationKeys(t *testing.T) {
	for name, tc := range map[string]struct {
		principal string
		want      sigv4.Principal
	}{
		"a member under OUs": {
			`,"OrgId":"` + orgID + `","OrgPaths":["` + orgID +
				`/r-ab12/ou-ab12-11111111/ou-ab12-22222222/"]`,
			sigv4.Principal{OrgID: orgID, OrgPaths: []string{
				orgID + "/r-ab12/ou-ab12-11111111/ou-ab12-22222222/",
			}},
		},
		"under the root":       {`,"OrgId":"` + orgID + `","OrgPaths":["` + orgID + `/r-ab12/"]`, sigv4.Principal{OrgID: orgID, OrgPaths: []string{orgID + "/r-ab12/"}}},
		"in no organization":   {``, sigv4.Principal{}},
		"organization unknown": {`,"OrgUnknown":true`, sigv4.Principal{OrgUnknown: true}},
		"an empty path list":   {`,"OrgPaths":[]`, sigv4.Principal{}},
	} {
		t.Run(name, func(t *testing.T) {
			got, err := newClient(t, answering(t, `,"PrincipalType":"User"`+tc.principal),
				rootKeyID, rootSecret).SigningKey(t.Context(), scope("AKIAAAAAAAAAAAAAAAAA", ""))
			if err != nil {
				t.Fatalf("signing key: %v", err)
			}
			p := got.Principal
			// reflect.DeepEqual tells an empty slice from nil.
			if p.OrgID != tc.want.OrgID || !reflect.DeepEqual(p.OrgPaths, tc.want.OrgPaths) ||
				p.OrgUnknown != tc.want.OrgUnknown {
				t.Fatalf("organization = %q %q %t, want %q %q %t", p.OrgID, p.OrgPaths,
					p.OrgUnknown, tc.want.OrgID, tc.want.OrgPaths, tc.want.OrgUnknown)
			}
		})
	}
}
