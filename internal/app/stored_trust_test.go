package app

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/smithy-go"
	"github.com/rs/zerolog"

	"tule.dev/identity/internal/contracts"
	"tule.dev/identity/servicerole"
)

// Trust policies tule.dev/policy v0.2.0 refuses: an AWS principal ARN needs
// a blank region and a 12-digit account, which v0.1.0 did not check, and no
// wildcard, which it did.
var looseTrust = map[string]string{
	"regional root":    trustFor("arn:aws:iam:us-east-1:000000000000:root"),
	"regional user":    trustFor("arn:aws:iam:us-east-1:000000000000:user/alice"),
	"short account":    trustFor("arn:aws:iam::12345:root"),
	"wildcard in name": trustFor("arn:aws:iam::000000000000:user/al*"),
}

func TestATrustPolicyNeedsAnIAMPrincipalARN(t *testing.T) {
	ctx := t.Context()
	url := startApp(t, t.TempDir(), nil)
	root := iamClient(url, rootCreds())
	createUserWithKey(t, root, "alice")
	check(t, createRoleWith(t, root, "r", trustFor("arn:aws:iam::000000000000:root")) == nil,
		"create the role")

	for name, doc := range looseTrust {
		t.Run(name, func(t *testing.T) {
			_, err := root.CreateRole(ctx, &iam.CreateRoleInput{
				RoleName: aws.String("loose"), AssumeRolePolicyDocument: aws.String(doc),
			})
			requireMalformedPrincipal(t, err)
			_, err = root.UpdateAssumeRolePolicy(ctx, &iam.UpdateAssumeRolePolicyInput{
				RoleName: aws.String("r"), PolicyDocument: aws.String(doc),
			})
			requireMalformedPrincipal(t, err)
		})
	}
}

func requireMalformedPrincipal(t *testing.T, err error) {
	t.Helper()
	var apiErr smithy.APIError
	check(t, errors.As(err, &apiErr) && apiErr.ErrorCode() == "MalformedPolicyDocument" &&
		apiErr.ErrorMessage() == "Invalid principal in policy",
		"got %v, want MalformedPolicyDocument: Invalid principal in policy", err)
}

// storePath is the store startApp opens in dir.
func storePath(dir string) string {
	return filepath.Join(dir, "nested", "identity.db")
}

// setStoredTrust writes the role's trust policy to the store directly, as an
// earlier release could have stored it.
func setStoredTrust(t *testing.T, dir, role, doc string) {
	t.Helper()
	db, err := sql.Open("sqlite", "file:"+storePath(dir))
	check(t, err == nil, "open the store: %v", err)
	defer func() { check(t, db.Close() == nil, "close the store") }()
	res, err := db.ExecContext(t.Context(),
		`UPDATE roles SET trust_policy = ? WHERE name = ?`, doc, role)
	check(t, err == nil, "update the trust policy: %v", err)
	n, err := res.RowsAffected()
	check(t, err == nil && n == 1, "updated %d roles, %v", n, err)
}

func TestAStoredTrustPolicyThatNoLongerParsesTrustsNoOne(t *testing.T) {
	dir := t.TempDir()
	url := startApp(t, dir, nil)
	root := iamClient(url, rootCreds())
	alice := createUserWithKey(t, root, "alice")
	_, err := root.PutUserPolicy(t.Context(), &iam.PutUserPolicyInput{
		UserName: aws.String("alice"), PolicyName: aws.String("assume"),
		PolicyDocument: aws.String(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow",` +
			`"Action":"sts:AssumeRole","Resource":"*"}]}`),
	})
	check(t, err == nil, "put user policy: %v", err)
	check(t, createRoleWith(t, root, "legacy", trustFor("arn:aws:iam::000000000000:root")) == nil,
		"create the role")
	check(t, assumeAs(t, url, alice, "legacy") == nil, "assume the role before")

	// The account's root ARN with a region, which v0.1.0 accepted as the
	// account and v0.2.0 refuses: AssumeRole answers AccessDenied, as for a
	// role that does not trust the caller, not an internal error.
	setStoredTrust(t, dir, "legacy", looseTrust["regional root"])
	requireCode(t, assumeAs(t, url, alice, "legacy"), "AccessDenied")

	// The assume-role endpoint answers NotTrusted.
	check(t, createRoleWith(t, root, "fn", trustFor("arn:aws:iam::000000000000:root")) == nil,
		"create the service role")
	setStoredTrust(t, dir, "fn", `{"Version":"2012-10-17","Statement":[{"Effect":"Allow",`+
		`"Principal":{"Service":"lambda.amazonaws.com",`+
		`"AWS":"arn:aws:iam:us-east-1:000000000000:root"},"Action":"sts:AssumeRole"}]}`)
	c, err := servicerole.New(servicerole.Config{
		Endpoint: url, AccessKeyID: testKeyID, SecretAccessKey: testSecret,
	})
	check(t, err == nil, "new service role client: %v", err)
	_, err = c.AssumeServiceRole(t.Context(), "arn:aws:iam::000000000000:role/fn", "invocation",
		"lambda.amazonaws.com", 0)
	check(t, errors.Is(err, servicerole.ErrNotTrusted), "assume the service role: got %v, want %v",
		err, servicerole.ErrNotTrusted)

	// The policy is shown as stored, and it can be rewritten.
	check(t, shownTrustOf(t, root, "legacy") == looseTrust["regional root"],
		"trust policy = %s", shownTrustOf(t, root, "legacy"))
	_, err = root.UpdateAssumeRolePolicy(t.Context(), &iam.UpdateAssumeRolePolicyInput{
		RoleName:       aws.String("legacy"),
		PolicyDocument: aws.String(trustFor("arn:aws:iam::000000000000:root")),
	})
	check(t, err == nil, "rewrite the trust policy: %v", err)
	check(t, assumeAs(t, url, alice, "legacy") == nil, "assume the rewritten role")
}

func TestTheAppStartsOnAStoredTrustPolicyThatNoLongerParses(t *testing.T) {
	dir := t.TempDir()
	url := startApp(t, dir, nil)
	root := iamClient(url, rootCreds())
	check(t, createRoleWith(t, root, "legacy", trustFor("arn:aws:iam::000000000000:root")) == nil,
		"create the role")
	setStoredTrust(t, dir, "legacy", looseTrust["regional root"])

	// A second app on the same store runs the startup check, and starts.
	url = startApp(t, dir, nil)
	check(t, shownTrustOf(t, iamClient(url, rootCreds()), "legacy") == looseTrust["regional root"],
		"the stored policy is left as it is")
}

// rolesStore is a store that has only the roles.
type rolesStore struct {
	contracts.IdentityProvider

	roles []contracts.Role
}

func (s rolesStore) AllRoles(context.Context) ([]contracts.Role, error) {
	return s.roles, nil
}

func TestTheStartupCheckReportsEachStoredTrustPolicyThatNoLongerParses(t *testing.T) {
	var out bytes.Buffer
	zl := zerolog.New(&out)
	logger, err := newZeroLogger(&zl)
	check(t, err == nil, "new logger: %v", err)

	store := rolesStore{roles: []contracts.Role{
		{
			ARN:         "arn:aws:iam::000000000000:role/ok",
			TrustPolicy: trustFor("arn:aws:iam::000000000000:root"),
		},
		{ARN: "arn:aws:iam::000000000000:role/regional", TrustPolicy: looseTrust["regional root"]},
		{ARN: "arn:aws:iam::000000000000:role/short", TrustPolicy: looseTrust["short account"]},
		// The placeholder trustdoc.ForCaller puts in place of an unbound
		// ARN is stored by nothing, but parses.
		{
			ARN:         "arn:aws:iam::000000000000:role/unbound",
			TrustPolicy: trustFor("arn:aws:iam::000000000000:unbound/none"),
		},
	}}
	check(t, checkStoredTrust(t.Context(), store, logger) == nil, "check the stored trust")

	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	check(t, len(lines) == 2, "logged %q, want one line per role that does not parse", lines)
	for i, role := range []string{"regional", "short"} {
		check(t, strings.Contains(lines[i], `"level":"warn"`) &&
			strings.Contains(lines[i], `"role":"arn:aws:iam::000000000000:role/`+role+`"`) &&
			strings.Contains(lines[i], `"error":"Invalid principal in policy"`),
			"line %d = %s", i, lines[i])
	}
}
