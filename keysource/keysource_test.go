package keysource_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
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
	if got.Principal != (sigv4.Principal{
		AccountID: "000000000000", ARN: "arn:aws:iam::000000000000:user/dev",
		AccessKeyID: aws.ToString(key.AccessKeyId),
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
