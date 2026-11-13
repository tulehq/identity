package principals_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/gasmod/gas/config"

	"tule.dev/identity/internal/app"
	"tule.dev/identity/internal/rootcall"
	"tule.dev/identity/principals"
)

const (
	rootKeyID  = "AKIAIOSFODNN7EXAMPLE"
	rootSecret = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
	account    = "000000000000"
)

// startIdentity runs the identity app on a fresh store and returns its URL.
func startIdentity(t *testing.T) string {
	t.Helper()
	t.Setenv("TULE_GasEnv", "testing")
	t.Setenv("TULE_Store_Path", filepath.Join(t.TempDir(), "identity.db"))
	t.Setenv("TULE_Auth_AccessKeyID", rootKeyID)
	t.Setenv("TULE_Auth_SecretAccessKey", rootSecret)
	cfg, err := app.LoadConfigFrom(config.NewEnvProvider(
		config.WithEnvSeparator("_"), config.WithEnvPrefix("TULE_")))
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	a, err := app.New(cfg)
	if err != nil {
		t.Fatalf("new app: %v", err)
	}
	if err = a.Start(context.Background()); err != nil {
		t.Fatalf("start app: %v", err)
	}
	srv := httptest.NewServer(a.Handler())
	t.Cleanup(func() {
		srv.Close()
		if sErr := a.Shutdown(context.Background()); sErr != nil {
			t.Errorf("shutdown: %v", sErr)
		}
	})
	return srv.URL
}

// newClient returns a client for url signing with the root key ID and
// secret.
func newClient(t *testing.T, url, secret string) *principals.Client {
	t.Helper()
	c, err := principals.New(principals.Config{
		Endpoint: url, AccessKeyID: rootKeyID, SecretAccessKey: secret,
	})
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	return c
}

func rootIAM(url string) *iam.Client {
	return iam.New(iam.Options{
		Region:           "us-east-1",
		BaseEndpoint:     aws.String(url),
		Credentials:      credentials.NewStaticCredentialsProvider(rootKeyID, rootSecret, ""),
		RetryMaxAttempts: 1,
	})
}

const trustAccount = `{"Version":"2012-10-17","Statement":[{"Effect":"Allow",` +
	`"Principal":{"AWS":"` + account + `"},"Action":"sts:AssumeRole"}]}`

// createUser creates the IAM user dev at path and returns its unique ID.
func createUser(t *testing.T, c *iam.Client, path string) string {
	t.Helper()
	out, err := c.CreateUser(t.Context(), &iam.CreateUserInput{
		UserName: aws.String("dev"), Path: aws.String(path),
	})
	if err != nil {
		t.Fatalf("create user dev: %v", err)
	}
	return aws.ToString(out.User.UserId)
}

// createRole creates a role and returns its unique ID.
func createRole(t *testing.T, c *iam.Client, path, name string) string {
	t.Helper()
	out, err := c.CreateRole(t.Context(), &iam.CreateRoleInput{
		RoleName: aws.String(name), Path: aws.String(path),
		AssumeRolePolicyDocument: aws.String(trustAccount),
	})
	if err != nil {
		t.Fatalf("create role %s: %v", name, err)
	}
	return aws.ToString(out.Role.RoleId)
}

func userARN(path, name string) string { return "arn:aws:iam::" + account + ":user" + path + name }
func roleARN(path, name string) string { return "arn:aws:iam::" + account + ":role" + path + name }

// bucketPolicy is an S3 bucket policy whose Principal names aws, and whose
// Deny's NotPrincipal names notAWS.
func bucketPolicy(aws, notAWS string) string {
	return `{"Version":"2012-10-17","Id":"p","Statement":[` +
		`{"Sid":"Grant","Effect":"Allow","Principal":{"AWS":` + aws + `},` +
		`"Action":"s3:GetObject","Resource":"arn:aws:s3:::bucket/*",` +
		`"Condition":{"ArnEquals":{"aws:PrincipalArn":"` + userARN("/", "dev") + `"}}},` +
		`{"Sid":"Fence","Effect":"Deny","NotPrincipal":{"AWS":` + notAWS + `},` +
		`"Action":"s3:DeleteObject","Resource":"arn:aws:s3:::bucket/*"},` +
		`{"Sid":"Svc","Effect":"Allow","Principal":{"Service":"logging.s3.amazonaws.com"},` +
		`"Action":"s3:PutObject","Resource":"arn:aws:s3:::bucket/*"}]}`
}

func TestBindNamesUsersAndRolesByUniqueID(t *testing.T) {
	url := startIdentity(t)
	ic := rootIAM(url)
	userID := createUser(t, ic, "/team/")
	roleID := createRole(t, ic, "/app/", "deployer")
	c := newClient(t, url, rootSecret)

	// A user and a role ARN are bound; an account ID, a root ARN, a session
	// ARN, "*" and a unique ID are kept, as are the service principal and
	// the ARN in the condition, which AWS does not convert.
	kept := `"` + account + `","arn:aws:iam::` + account + `:root",` +
		`"arn:aws:sts::` + account + `:assumed-role/deployer/s","*","AIDAKEPTEXAMPLE12345"`
	doc := bucketPolicy(
		`["`+userARN("/team/", "dev")+`","`+roleARN("/app/", "deployer")+`",`+kept+`]`,
		`["`+account+`","`+roleARN("/app/", "deployer")+`"]`)
	got, err := c.Bind(t.Context(), doc)
	if err != nil {
		t.Fatalf("bind: %v", err)
	}
	want := bucketPolicy(`["`+userID+`","`+roleID+`",`+kept+`]`, `["`+account+`","`+roleID+`"]`)
	if got != want {
		t.Fatalf("bound =\n%s\nwant\n%s", got, want)
	}

	// Shown, the IDs are the ARNs again: the document as it was sent.
	shown, err := c.Show(t.Context(), got)
	if err != nil {
		t.Fatalf("show: %v", err)
	}
	if shown != doc {
		t.Fatalf("shown =\n%s\nwant\n%s", shown, doc)
	}
}

func TestBindKeepsADocumentWithoutUsersOrRoles(t *testing.T) {
	url := startIdentity(t)
	c := newClient(t, url, rootSecret)
	doc := "{\n  \"Version\": \"2012-10-17\",\n  \"Statement\": {\"Effect\": \"Allow\", " +
		"\"Principal\": \"*\", \"Action\": \"s3:GetObject\", \"Resource\": \"*\"}\n}"
	for name, f := range map[string]func(context.Context, string) (string, error){
		"bind": c.Bind, "show": c.Show,
	} {
		got, err := f(t.Context(), doc)
		if err != nil || got != doc {
			t.Errorf("%s = %q, %v; want the document as it is", name, got, err)
		}
	}
}

func TestBindRefusesAPrincipalThatDoesNotExist(t *testing.T) {
	url := startIdentity(t)
	ic := rootIAM(url)
	createUser(t, ic, "/")
	c := newClient(t, url, rootSecret)

	// The ARN of a user with another path, of another case, or of no user
	// at all names nobody: a Principal's path and name match with their
	// case.
	for _, missing := range []string{
		userARN("/other/", "dev"), userARN("/", "Dev"), roleARN("/", "dev"),
		"arn:aws:iam::111122223333:user/dev",
	} {
		doc := bucketPolicy(`["`+userARN("/", "dev")+`","`+missing+`"]`, `"`+account+`"`)
		_, err := c.Bind(t.Context(), doc)
		var invalid *principals.InvalidPrincipalError
		if !errors.As(err, &invalid) || invalid.ARN != missing ||
			!errors.Is(err, principals.ErrInvalidPrincipal) {
			t.Errorf("bind naming %s: %v; want an invalid principal %s", missing, err, missing)
		}
	}
}

func TestARecreatedPrincipalIsAnotherPrincipal(t *testing.T) {
	url := startIdentity(t)
	ic := rootIAM(url)
	c := newClient(t, url, rootSecret)
	oldUser := createUser(t, ic, "/")
	oldRole := createRole(t, ic, "/", "deployer")
	doc := bucketPolicy(`["`+userARN("/", "dev")+`","`+roleARN("/", "deployer")+`"]`,
		`"`+account+`"`)
	bound, err := c.Bind(t.Context(), doc)
	if err != nil {
		t.Fatalf("bind: %v", err)
	}

	if _, err = ic.DeleteUser(t.Context(), &iam.DeleteUserInput{
		UserName: aws.String("dev"),
	}); err != nil {
		t.Fatalf("delete user: %v", err)
	}
	if _, err = ic.DeleteRole(t.Context(), &iam.DeleteRoleInput{
		RoleName: aws.String("deployer"),
	}); err != nil {
		t.Fatalf("delete role: %v", err)
	}
	newUser := createUser(t, ic, "/")
	newRole := createRole(t, ic, "/", "deployer")
	if newUser == oldUser || newRole == oldRole {
		t.Fatal("a recreated principal has its old unique ID")
	}

	// The stored policy shows the old IDs, which no principal has now.
	shown, err := c.Show(t.Context(), bound)
	if err != nil {
		t.Fatalf("show: %v", err)
	}
	if want := bucketPolicy(`["`+oldUser+`","`+oldRole+`"]`, `"`+account+`"`); shown != want {
		t.Fatalf("shown =\n%s\nwant\n%s", shown, want)
	}

	// Saved again, the ARNs bind to the new principals.
	rebound, err := c.Bind(t.Context(), doc)
	if err != nil {
		t.Fatalf("bind again: %v", err)
	}
	if want := bucketPolicy(`["`+newUser+`","`+newRole+`"]`, `"`+account+`"`); rebound != want {
		t.Fatalf("rebound =\n%s\nwant\n%s", rebound, want)
	}
}

func TestShowSplitsLargeSets(t *testing.T) {
	url := startIdentity(t)
	c := newClient(t, url, rootSecret)

	// More IDs than one call may name, none of a principal: each stays.
	ids := make([]string, principals.MaxBatch+500)
	for i := range ids {
		ids[i] = fmt.Sprintf(`"AIDA%016d"`, i)
	}
	doc := bucketPolicy("["+strings.Join(ids, ",")+"]", `"`+account+`"`)
	got, err := c.Show(t.Context(), doc)
	if err != nil || got != doc {
		t.Fatalf("show = %v; want the document as it is", err)
	}
}

// post signs body as a call to the endpoint with the key, and returns the
// status and the decoded error code.
func post(t *testing.T, url, keyID, secret, body string) (int, string) {
	t.Helper()
	caller, err := rootcall.New(url, keyID, secret, nil)
	if err != nil {
		t.Fatalf("caller: %v", err)
	}
	status, raw, err := caller.Post(t.Context(), principals.Path, []byte(body), 1<<20)
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	var e principals.ErrorResponse
	_ = json.Unmarshal(raw, &e)
	return status, e.Code
}

func TestTheEndpointRefusesMalformedRequests(t *testing.T) {
	url := startIdentity(t)
	tooMany := make([]string, principals.MaxBatch+1)
	for i := range tooMany {
		tooMany[i] = fmt.Sprintf(`"AIDA%016d"`, i)
	}
	for name, body := range map[string]string{
		"not JSON":      `{`,
		"an account":    `{"Arns":["` + account + `"]}`,
		"a root ARN":    `{"Arns":["arn:aws:iam::` + account + `:root"]}`,
		"a session ARN": `{"Arns":["arn:aws:sts::` + account + `:assumed-role/r/s"]}`,
		"a key ID":      `{"Ids":["AKIAIOSFODNN7EXAMPLE"]}`,
		"lower case":    `{"Ids":["aidaexample123456789"]}`,
		"too many":      `{"Ids":[` + strings.Join(tooMany, ",") + `]}`,
	} {
		status, code := post(t, url, rootKeyID, rootSecret, body)
		if status != http.StatusBadRequest || code != principals.CodeInvalidRequest {
			t.Errorf("%s: %d %s; want 400 %s", name, status, code, principals.CodeInvalidRequest)
		}
	}
}

func TestOnlyTheRootKeyMayResolve(t *testing.T) {
	url := startIdentity(t)
	ic := rootIAM(url)
	createUser(t, ic, "/")
	key, err := ic.CreateAccessKey(t.Context(), &iam.CreateAccessKeyInput{
		UserName: aws.String("dev"),
	})
	if err != nil {
		t.Fatalf("create access key: %v", err)
	}
	status, code := post(t, url, aws.ToString(key.AccessKey.AccessKeyId),
		aws.ToString(key.AccessKey.SecretAccessKey), `{"Arns":["`+userARN("/", "dev")+`"]}`)
	if status != http.StatusForbidden || code != "UnknownAccessKey" {
		t.Fatalf("a user's key: %d %s; want 403 UnknownAccessKey", status, code)
	}

	_, err = newClient(t, url, "wrong").Bind(t.Context(),
		bucketPolicy(`"`+userARN("/", "dev")+`"`, `"`+account+`"`))
	var e *principals.Error
	if !errors.As(err, &e) || e.Status != http.StatusForbidden {
		t.Fatalf("a wrong secret: %v; want a 403 *Error", err)
	}
}

func TestTheClientRefusesAnInvalidAnswer(t *testing.T) {
	for name, answer := range map[string]string{
		"an ARN it did not ask for": `{"Ids":{"` + roleARN("/", "other") + `":"AROAEXAMPLE123456789"}}`,
		"an ARN to a non-ID":        `{"Ids":{"` + userARN("/", "dev") + `":"dev"}}`,
		"an ID to a non-ARN":        `{"Arns":{"AIDAEXAMPLE123456789":"*"}}`,
	} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(answer))
		}))
		c := newClient(t, srv.URL, rootSecret)
		doc := bucketPolicy(`["`+userARN("/", "dev")+`","AIDAEXAMPLE123456789"]`, `"`+account+`"`)
		_, bErr := c.Bind(t.Context(), doc)
		_, sErr := c.Show(t.Context(), doc)
		var e *principals.Error
		if !errors.As(bErr, &e) && !errors.As(sErr, &e) {
			t.Errorf("%s: bind %v, show %v; want an *Error", name, bErr, sErr)
		} else if e.Code != principals.CodeInvalidResponse {
			t.Errorf("%s: code %s; want %s", name, e.Code, principals.CodeInvalidResponse)
		}
		srv.Close()
	}
}

func TestNewChecksItsConfig(t *testing.T) {
	for _, cfg := range []principals.Config{
		{Endpoint: "localhost:9030", AccessKeyID: rootKeyID, SecretAccessKey: rootSecret},
		{Endpoint: "http://localhost:9030", SecretAccessKey: rootSecret},
		{Endpoint: "http://localhost:9030", AccessKeyID: rootKeyID},
	} {
		if _, err := principals.New(cfg); err == nil {
			t.Errorf("New(%+v) succeeded", cfg)
		}
	}
}
