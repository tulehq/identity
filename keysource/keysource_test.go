package keysource_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/gasmod/gas/config"
	"tule.dev/sigv4"

	"tule.dev/identity/internal/app"
	"tule.dev/identity/keysource"
)

const (
	rootKeyID  = "AKIAIOSFODNN7EXAMPLE"
	rootSecret = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
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

func newClient(t *testing.T, url, keyID, secret string) *keysource.Client {
	t.Helper()
	c, err := keysource.New(keysource.Config{
		Endpoint: url, AccessKeyID: keyID, SecretAccessKey: secret,
	})
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	return c
}

// userKey creates a user with an access key through IAM and returns the key.
func userKey(t *testing.T, url string) *iamtypes.AccessKey {
	t.Helper()
	c := iam.New(iam.Options{
		Region:           "us-east-1",
		BaseEndpoint:     aws.String(url),
		Credentials:      credentials.NewStaticCredentialsProvider(rootKeyID, rootSecret, ""),
		RetryMaxAttempts: 1,
	})
	if _, err := c.CreateUser(t.Context(), &iam.CreateUserInput{
		UserName: aws.String("dev"),
	}); err != nil {
		t.Fatalf("create user: %v", err)
	}
	out, err := c.CreateAccessKey(t.Context(), &iam.CreateAccessKeyInput{
		UserName: aws.String("dev"),
	})
	if err != nil {
		t.Fatalf("create access key: %v", err)
	}
	return out.AccessKey
}

func scope(keyID, token string) sigv4.Scope {
	return sigv4.Scope{
		AccessKeyID: keyID, SessionToken: token,
		Date: "20261113", Region: "eu-west-1", Service: "s3",
	}
}

func TestTheClientHandsOutDerivedKeys(t *testing.T) {
	url := startIdentity(t)
	key := userKey(t, url)
	c := newClient(t, url, rootKeyID, rootSecret)

	got, err := c.SigningKey(t.Context(), scope(aws.ToString(key.AccessKeyId), ""))
	if err != nil {
		t.Fatalf("signing key: %v", err)
	}
	want := sigv4.DeriveSigningKey(aws.ToString(key.SecretAccessKey), "20261113",
		"eu-west-1", "s3")
	if string(got.Signing) != string(want) {
		t.Fatal("the signing key is not the one the secret derives")
	}
	user, err := iamRoot(url).GetUser(t.Context(), &iam.GetUserInput{UserName: aws.String("dev")})
	if err != nil {
		t.Fatalf("get user: %v", err)
	}
	if !reflect.DeepEqual(got.Principal, sigv4.Principal{
		AccountID: "000000000000", ARN: "arn:aws:iam::000000000000:user/dev",
		PrincipalARN: "arn:aws:iam::000000000000:user/dev", UserID: aws.ToString(user.User.UserId),
		AccessKeyID: aws.ToString(key.AccessKeyId), Type: sigv4.PrincipalTypeUser,
	}) {
		t.Fatalf("principal = %+v", got.Principal)
	}

	_, err = c.SigningKey(t.Context(), scope("AKIAAAAAAAAAAAAAAAAA", ""))
	if !errors.Is(err, sigv4.ErrUnknownAccessKey) ||
		errors.Is(err, keysource.ErrInactiveAccessKey) {
		t.Fatalf("unknown key = %v", err)
	}
	_, err = c.SigningKey(t.Context(), scope(aws.ToString(key.AccessKeyId), "token"))
	if !errors.Is(err, sigv4.ErrInvalidSessionToken) {
		t.Fatalf("long-term key with a token = %v", err)
	}
}

func TestAServiceVerifiesThroughTheClient(t *testing.T) {
	url := startIdentity(t)
	key := userKey(t, url)
	v, err := sigv4.New(newClient(t, url, rootKeyID, rootSecret))
	if err != nil {
		t.Fatalf("new verifier: %v", err)
	}

	// A request to some other service, signed with the IAM user's key.
	body := `{"Name":"x"}`
	req := httptest.NewRequest(http.MethodPost, "http://secrets.local/", strings.NewReader(body))
	sum := sha256.Sum256([]byte(body))
	if err = v4.NewSigner().SignHTTP(t.Context(), aws.Credentials{
		AccessKeyID:     aws.ToString(key.AccessKeyId),
		SecretAccessKey: aws.ToString(key.SecretAccessKey),
	}, req, hex.EncodeToString(sum[:]), "secretsmanager", "us-east-1", time.Now()); err != nil {
		t.Fatalf("sign: %v", err)
	}
	verified, err := v.Verify(req)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if p, _ := sigv4.PrincipalFrom(
		verified.Context(),
	); p.ARN != "arn:aws:iam::000000000000:user/dev" {
		t.Fatalf("principal = %+v", p)
	}
}

func TestOnlyTheRootKeyMayAsk(t *testing.T) {
	url := startIdentity(t)
	key := userKey(t, url)

	for name, c := range map[string]*keysource.Client{
		"user key":     newClient(t, url, aws.ToString(key.AccessKeyId), aws.ToString(key.SecretAccessKey)),
		"wrong secret": newClient(t, url, rootKeyID, "not-the-secret"),
	} {
		t.Run(name, func(t *testing.T) {
			_, err := c.SigningKey(t.Context(), scope(rootKeyID, ""))
			var e *keysource.Error
			if !errors.As(err, &e) || e.Status != http.StatusForbidden {
				t.Fatalf("got %v, want a 403 *keysource.Error", err)
			}
		})
	}
}

func TestNewChecksItsConfig(t *testing.T) {
	for name, cfg := range map[string]keysource.Config{
		"no endpoint":       {AccessKeyID: rootKeyID, SecretAccessKey: rootSecret},
		"relative endpoint": {Endpoint: "localhost:9030", AccessKeyID: rootKeyID, SecretAccessKey: rootSecret},
		"no key":            {Endpoint: "http://localhost:9030"},
	} {
		if _, err := keysource.New(cfg); err == nil {
			t.Errorf("%s: New succeeded", name)
		}
	}
}

func TestTheClientReportsRootAndPolicies(t *testing.T) {
	url := startIdentity(t)
	key := userKey(t, url)
	c := newClient(t, url, rootKeyID, rootSecret)

	got, err := c.SigningKey(t.Context(), scope(rootKeyID, ""))
	if err != nil || !got.Principal.Root || got.Principal.Policies != nil {
		t.Fatalf("root key = %+v, %v; want Root with no policies", got.Principal, err)
	}

	doc := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:*","Resource":"*"}]}`
	if _, err = iamRoot(url).PutUserPolicy(t.Context(), &iam.PutUserPolicyInput{
		UserName: aws.String("dev"), PolicyName: aws.String("s3"), PolicyDocument: aws.String(doc),
	}); err != nil {
		t.Fatalf("put user policy: %v", err)
	}
	got, err = c.SigningKey(t.Context(), scope(aws.ToString(key.AccessKeyId), ""))
	if err != nil || got.Principal.Root || len(got.Principal.Policies) != 1 ||
		string(got.Principal.Policies[0]) != doc {
		t.Fatalf("user key = %+v, %v; want its one policy", got.Principal, err)
	}
}

func iamRoot(url string) *iam.Client {
	return iam.New(iam.Options{
		Region:           "us-east-1",
		BaseEndpoint:     aws.String(url),
		Credentials:      credentials.NewStaticCredentialsProvider(rootKeyID, rootSecret, ""),
		RetryMaxAttempts: 1,
	})
}

// versionedAnswer is a signing-key response as JSON, so a test can tell a
// field the endpoint left out from one it sent empty.
type versionedAnswer struct {
	Version   any
	Principal map[string]any
}

// askAt posts the scope of the root key to the endpoint at version, 0 for
// none, as a client of that version sends it, and returns the answer.
func askAt(t *testing.T, url string, version int) versionedAnswer {
	t.Helper()
	body := `{"AccessKeyId":"` + rootKeyID + `","Date":"20261113","Region":"eu-west-1","Service":"s3"`
	if version > 0 {
		body += `,"Version":` + strconv.Itoa(version)
	}
	body += `}`
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, url+keysource.Path,
		strings.NewReader(body))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	sum := sha256.Sum256([]byte(body))
	if err = v4.NewSigner().SignHTTP(t.Context(), aws.Credentials{
		AccessKeyID: rootKeyID, SecretAccessKey: rootSecret,
	}, req, hex.EncodeToString(sum[:]), keysource.SigningName, keysource.SigningRegion,
		time.Now()); err != nil {
		t.Fatalf("sign: %v", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	var out versionedAnswer
	if err = json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d, body %+v", resp.StatusCode, out)
	}
	return out
}

// attributeFields are the fields version 3 added to the principal.
var attributeFields = []string{"PrincipalArn", "UserId", "PrincipalType", "Tags"}

// organizationFields are the fields version 4 added to the principal.
var organizationFields = []string{"OrgId", "OrgPaths", "OrgUnknown"}

func TestAnUnversionedRequestIsAnsweredAsV010(t *testing.T) {
	out := askAt(t, startIdentity(t), 0)
	p := out.Principal
	if out.Version != nil || p["Arn"] != "arn:aws:iam::000000000000:root" ||
		p["Root"] != nil || p["Policies"] != nil {
		t.Fatalf("answer = %+v, want v0.1.0's fields only", out)
	}
	for _, f := range append(attributeFields, organizationFields...) {
		if _, ok := p[f]; ok {
			t.Fatalf("principal = %v, want no %s", p, f)
		}
	}
}

// A client of identity v0.3.0 asks at version 2, and is answered as v0.3.0
// answered it: with Root and Policies, but none of version 3's fields.
func TestAVersion2RequestIsAnsweredAtVersion2(t *testing.T) {
	url := startIdentity(t)
	out := askAt(t, url, keysource.VersionPolicies)
	p := out.Principal
	if out.Version != float64(keysource.VersionPolicies) || p["Root"] != true {
		t.Fatalf("answer = %+v, want version 2 with Root", out)
	}
	for _, f := range append(attributeFields, organizationFields...) {
		if _, ok := p[f]; ok {
			t.Fatalf("principal = %v, want no %s", p, f)
		}
	}

	// A client of identity v0.4.1 asks at version 3, and is answered without
	// the organization keys, and without asking the accounts service.
	out = askAt(t, url, keysource.VersionAttributes)
	if out.Version != float64(keysource.VersionAttributes) ||
		out.Principal["PrincipalType"] != "Account" {
		t.Fatalf("answer = %+v, want version 3 with the principal's type", out)
	}
	for _, f := range organizationFields {
		if _, ok := out.Principal[f]; ok {
			t.Fatalf("principal = %v, want no %s", out.Principal, f)
		}
	}
	// A client newer than the endpoint is answered at the endpoint's version.
	if out = askAt(t, url, keysource.VersionOrganization+1); out.Version !=
		float64(keysource.VersionOrganization) {
		t.Fatalf("answer = %+v, want version 4", out)
	}
}

func TestTheClientRefusesAnEndpointThatReportsNoPolicies(t *testing.T) {
	// An identity older than v0.2.0 answers without a Version.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"Principal":{"AccountId":"000000000000",` +
			`"Arn":"arn:aws:iam::000000000000:user/dev","AccessKeyId":"AKIA"},"SigningKey":"AA=="}`))
	}))
	t.Cleanup(srv.Close)

	_, err := newClient(t, srv.URL, rootKeyID, rootSecret).SigningKey(t.Context(),
		scope("AKIAAAAAAAAAAAAAAAAA", ""))
	var e *keysource.Error
	if !errors.As(err, &e) || e.Code != keysource.CodeVersionUnsupported {
		t.Fatalf("got %v, want a %s *keysource.Error", err, keysource.CodeVersionUnsupported)
	}
}

func TestTheClientRefusesAnEndpointThatReportsNoAttributes(t *testing.T) {
	// Identity v0.3.0 answers at version 2, with no principal attributes.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"Version":2,"Principal":{"AccountId":"000000000000",` +
			`"Arn":"arn:aws:iam::000000000000:user/dev","AccessKeyId":"AKIA"},"SigningKey":"AA=="}`))
	}))
	t.Cleanup(srv.Close)

	_, err := newClient(t, srv.URL, rootKeyID, rootSecret).SigningKey(t.Context(),
		scope("AKIAAAAAAAAAAAAAAAAA", ""))
	var e *keysource.Error
	if !errors.As(err, &e) || e.Code != keysource.CodeVersionUnsupported {
		t.Fatalf("got %v, want a %s *keysource.Error", err, keysource.CodeVersionUnsupported)
	}
}

func TestTheClientRefusesAnEndpointThatReportsNoOrganization(t *testing.T) {
	// Identity v0.4.1 answers at version 3, with no organization keys.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"Version":3,"Principal":{"AccountId":"000000000000",` +
			`"Arn":"arn:aws:iam::000000000000:user/dev","AccessKeyId":"AKIA",` +
			`"PrincipalType":"User"},"SigningKey":"AA=="}`))
	}))
	t.Cleanup(srv.Close)

	_, err := newClient(t, srv.URL, rootKeyID, rootSecret).SigningKey(t.Context(),
		scope("AKIAAAAAAAAAAAAAAAAA", ""))
	var e *keysource.Error
	if !errors.As(err, &e) || e.Code != keysource.CodeVersionUnsupported {
		t.Fatalf("got %v, want a %s *keysource.Error", err, keysource.CodeVersionUnsupported)
	}
}

func TestTheClientRefusesAResponseOverTheBound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		pad := strings.Repeat(" ", keysource.MaxResponseSize)
		_, _ = w.Write([]byte(`{"Version":3,"Principal":{"Arn":"` + pad + `"}}`))
	}))
	t.Cleanup(srv.Close)

	_, err := newClient(t, srv.URL, rootKeyID, rootSecret).SigningKey(t.Context(),
		scope("AKIAAAAAAAAAAAAAAAAA", ""))
	if err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("got %v, want the response refused as too large", err)
	}
}
