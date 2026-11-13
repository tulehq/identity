package servicerole_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	neturl "net/url"
	"path/filepath"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/aws/smithy-go"
	"github.com/gasmod/gas/config"

	"tule.dev/identity/internal/app"
	"tule.dev/identity/servicerole"
)

const (
	rootKeyID  = "AKIAIOSFODNN7EXAMPLE"
	rootSecret = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
	account    = "000000000000"
	lambda     = "lambda.amazonaws.com"
)

func roleARN(name string) string { return "arn:aws:iam::" + account + ":role/" + name }

// lambdaTrust is the Lambda execution role's trust policy (the Lambda
// Developer Guide, Lambda execution role).
const lambdaTrust = `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":` +
	`{"Service":"lambda.amazonaws.com"},"Action":"sts:AssumeRole"}]}`

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

func client(t *testing.T, url, keyID, secret string) *servicerole.Client {
	t.Helper()
	c, err := servicerole.New(servicerole.Config{
		Endpoint: url, AccessKeyID: keyID, SecretAccessKey: secret,
	})
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	return c
}

func creds(c aws.Credentials) aws.CredentialsProvider {
	return credentials.NewStaticCredentialsProvider(
		c.AccessKeyID,
		c.SecretAccessKey,
		c.SessionToken,
	)
}

func iamAs(url string, c aws.Credentials) *iam.Client {
	return iam.New(iam.Options{
		Region: "us-east-1", BaseEndpoint: aws.String(url), Credentials: creds(c),
		RetryMaxAttempts: 1,
	})
}

func stsAs(url string, c aws.Credentials) *sts.Client {
	return sts.New(sts.Options{
		Region: "us-east-1", BaseEndpoint: aws.String(url), Credentials: creds(c),
		RetryMaxAttempts: 1,
	})
}

func rootIAM(url string) *iam.Client {
	return iamAs(url, aws.Credentials{AccessKeyID: rootKeyID, SecretAccessKey: rootSecret})
}

func createRole(t *testing.T, url, name, trust string, maxSession int32) {
	t.Helper()
	in := &iam.CreateRoleInput{
		RoleName:                 aws.String(name),
		AssumeRolePolicyDocument: aws.String(trust),
	}
	if maxSession > 0 {
		in.MaxSessionDuration = aws.Int32(maxSession)
	}
	if _, err := rootIAM(url).CreateRole(t.Context(), in); err != nil {
		t.Fatalf("create role %s: %v", name, err)
	}
}

func sessionCreds(s *servicerole.Session) aws.Credentials {
	return aws.Credentials{
		AccessKeyID:     s.Credentials.AccessKeyID,
		SecretAccessKey: s.Credentials.SecretAccessKey,
		SessionToken:    s.Credentials.SessionToken,
	}
}

func requireCode(t *testing.T, err error, code string) {
	t.Helper()
	var apiErr smithy.APIError
	if !errors.As(err, &apiErr) || apiErr.ErrorCode() != code {
		t.Fatalf("got %v, want error code %s", err, code)
	}
}

// assumeFor assumes fn as lambda for d and checks the session's ARN and
// expiration.
func assumeFor(t *testing.T, c *servicerole.Client, d time.Duration) *servicerole.Session {
	t.Helper()
	before := time.Now()
	s, err := c.AssumeServiceRole(t.Context(), roleARN("fn"), "invocation", lambda, d)
	if err != nil {
		t.Fatalf("assume the role as lambda: %v", err)
	}
	exp := s.Credentials.Expiration
	if s.AssumedRoleUser.Arn != "arn:aws:sts::"+account+":assumed-role/fn/invocation" ||
		exp.Before(before.Add(d-time.Second)) || exp.After(time.Now().Add(d+time.Second)) {
		t.Fatalf("session = %+v", s)
	}
	return s
}

func TestAServiceAssumesARoleThatTrustsIt(t *testing.T) {
	ctx := t.Context()
	url := startIdentity(t)
	createRole(t, url, "fn", lambdaTrust, 0)
	if _, err := rootIAM(url).PutRolePolicy(ctx, &iam.PutRolePolicyInput{
		RoleName: aws.String("fn"), PolicyName: aws.String("list"),
		PolicyDocument: aws.String(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow",` +
			`"Action":"iam:ListRoles","Resource":"*"}]}`),
	}); err != nil {
		t.Fatalf("put role policy: %v", err)
	}
	c := client(t, url, rootKeyID, rootSecret)

	s := assumeFor(t, c, 15*time.Minute)
	wantARN := "arn:aws:sts::" + account + ":assumed-role/fn/invocation"

	// The credentials are an ordinary session of the role, with its policies.
	sc := sessionCreds(s)
	me, err := stsAs(url, sc).GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil || aws.ToString(me.Arn) != wantARN ||
		aws.ToString(me.UserId) != s.AssumedRoleUser.AssumedRoleID {
		t.Fatalf("caller identity = %+v, %v", me, err)
	}
	if _, err = iamAs(url, sc).ListRoles(ctx, &iam.ListRolesInput{}); err != nil {
		t.Fatalf("list roles as the session: %v", err)
	}
	_, err = iamAs(url, sc).ListUsers(ctx, &iam.ListUsersInput{})
	requireCode(t, err, "AccessDenied")
}

func TestAServiceSessionLastsAnHourByDefault(t *testing.T) {
	url := startIdentity(t)
	createRole(t, url, "fn", lambdaTrust, 0)
	s, err := client(t, url, rootKeyID, rootSecret).AssumeServiceRole(t.Context(),
		roleARN("fn"), "default", lambda, 0)
	if err != nil || s.Credentials.Expiration.Before(time.Now().Add(59*time.Minute)) ||
		s.Credentials.Expiration.After(time.Now().Add(61*time.Minute)) {
		t.Fatalf("default duration = %+v, %v", s, err)
	}
}

func TestTheRefusalsCanBeToldApart(t *testing.T) {
	ctx := t.Context()
	url := startIdentity(t)
	createRole(t, url, "fn", lambdaTrust, 0)
	createRole(t, url, "long", lambdaTrust, 7200)
	createRole(t, url, "acct", `{"Version":"2012-10-17","Statement":[{"Effect":"Allow",`+
		`"Principal":{"AWS":"`+account+`"},"Action":"sts:AssumeRole"}]}`, 0)
	c := client(t, url, rootKeyID, rootSecret)

	for name, tc := range map[string]struct {
		want     error
		role     string
		service  string
		duration time.Duration
	}{
		"another service":        {servicerole.ErrNotTrusted, "fn", "ecs-tasks.amazonaws.com", 0},
		"an AWS-trusting role":   {servicerole.ErrNotTrusted, "acct", lambda, 0},
		"no such role":           {servicerole.ErrNoSuchRole, "missing", lambda, 0},
		"the name in other case": {servicerole.ErrNoSuchRole, "FN", lambda, 0},
		"under 900 seconds":      {servicerole.ErrInvalidDuration, "fn", lambda, 899 * time.Second},
		"over 43200 seconds":     {servicerole.ErrInvalidDuration, "long", lambda, 43201 * time.Second},
		"over the role's max":    {servicerole.ErrInvalidDuration, "fn", lambda, 3601 * time.Second},
		"not whole seconds":      {servicerole.ErrInvalidDuration, "fn", lambda, 1500 * time.Millisecond},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := c.AssumeServiceRole(ctx, roleARN(tc.role), "s1", tc.service, tc.duration)
			if !errors.Is(err, tc.want) {
				t.Fatalf("got %v, want %v", err, tc.want)
			}
		})
	}
	if _, err := c.AssumeServiceRole(
		ctx,
		roleARN("long"),
		"s1",
		lambda,
		7200*time.Second,
	); err != nil {
		t.Fatalf("assume for the role's maximum: %v", err)
	}

	for name, service := range map[string]string{
		"a bare name": "lambda", "an ARN": "arn:aws:iam::" + account + ":root", "empty": "",
	} {
		t.Run("service principal "+name, func(t *testing.T) {
			_, err := c.AssumeServiceRole(ctx, roleARN("fn"), "s1", service, 0)
			var e *servicerole.Error
			if !errors.As(err, &e) || e.Status != http.StatusBadRequest ||
				e.Code != servicerole.CodeInvalidRequest {
				t.Fatalf("got %v, want 400 %s", err, servicerole.CodeInvalidRequest)
			}
		})
	}
}

func TestOnlyTheRootKeyMayAssumeAsAService(t *testing.T) {
	ctx := t.Context()
	url := startIdentity(t)
	createRole(t, url, "fn", lambdaTrust, 0)
	root := rootIAM(url)
	if _, err := root.CreateUser(
		ctx,
		&iam.CreateUserInput{UserName: aws.String("dev")},
	); err != nil {
		t.Fatalf("create user: %v", err)
	}
	key, err := root.CreateAccessKey(ctx, &iam.CreateAccessKeyInput{UserName: aws.String("dev")})
	if err != nil {
		t.Fatalf("create key: %v", err)
	}
	userKey := aws.Credentials{
		AccessKeyID:     aws.ToString(key.AccessKey.AccessKeyId),
		SecretAccessKey: aws.ToString(key.AccessKey.SecretAccessKey),
	}

	for name, c := range map[string]*servicerole.Client{
		"a user key":   client(t, url, userKey.AccessKeyID, userKey.SecretAccessKey),
		"wrong secret": client(t, url, rootKeyID, "not-the-secret"),
	} {
		t.Run(name, func(t *testing.T) {
			_, aErr := c.AssumeServiceRole(ctx, roleARN("fn"), "s1", lambda, 0)
			var e *servicerole.Error
			if !errors.As(aErr, &e) || e.Status != http.StatusForbidden {
				t.Fatalf("got %v, want a 403 *servicerole.Error", aErr)
			}
		})
	}

	// Nor does a role that trusts a service trust a user through STS.
	_, err = stsAs(url, userKey).AssumeRole(ctx, &sts.AssumeRoleInput{
		RoleArn: aws.String(roleARN("fn")), RoleSessionName: aws.String("s1"),
	})
	requireCode(t, err, "AccessDenied")
}

func TestAssumingAsAServiceChangesNoRole(t *testing.T) {
	ctx := t.Context()
	url := startIdentity(t)
	trust := lambdaTrust
	createRole(t, url, "fn", trust, 0)
	c := client(t, url, rootKeyID, rootSecret)

	if _, err := c.AssumeServiceRole(ctx, roleARN("fn"), "s1", lambda, 0); err != nil {
		t.Fatalf("assume the role: %v", err)
	}
	got, err := rootIAM(url).GetRole(ctx, &iam.GetRoleInput{RoleName: aws.String("fn")})
	if err != nil {
		t.Fatalf("get the role: %v", err)
	}
	doc, err := neturl.QueryUnescape(aws.ToString(got.Role.AssumeRolePolicyDocument))
	if err != nil || doc != trust {
		t.Fatalf("trust policy after = %s, %v; want %s", doc, err, trust)
	}

	// A member account's OrganizationAccountAccessRole is not created here.
	_, err = c.AssumeServiceRole(ctx,
		"arn:aws:iam::123456789012:role/OrganizationAccountAccessRole", "s1", lambda, 0)
	if !errors.Is(err, servicerole.ErrNoSuchRole) {
		t.Fatalf("got %v, want %v", err, servicerole.ErrNoSuchRole)
	}
}

// conditionedTrust trusts lambda.amazonaws.com when the condition holds.
func conditionedTrust(operator, key, value string) string {
	return `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":` +
		`{"Service":"lambda.amazonaws.com"},"Action":"sts:AssumeRole","Condition":` +
		`{"` + operator + `":{"` + key + `":"` + value + `"}}}]}`
}

func TestTheSourceIsSuppliedToTheTrustPolicy(t *testing.T) {
	ctx := t.Context()
	url := startIdentity(t)
	const (
		fn1 = "arn:aws:lambda:us-east-1:" + account + ":function:one"
		fn2 = "arn:aws:lambda:us-east-1:" + account + ":function:two"
	)
	createRole(t, url, "by-arn", conditionedTrust("ArnEquals", "aws:SourceArn", fn1), 0)
	createRole(t, url, "by-account",
		conditionedTrust("StringEquals", "aws:SourceAccount", account), 0)
	c := client(t, url, rootKeyID, rootSecret)

	for name, tc := range map[string]struct {
		want error
		role string
		opts []servicerole.Option
	}{
		"the function's ARN": {nil, "by-arn", []servicerole.Option{servicerole.WithSourceArn(fn1)}},
		"another function":   {servicerole.ErrNotTrusted, "by-arn", []servicerole.Option{servicerole.WithSourceArn(fn2)}},
		"no source ARN":      {servicerole.ErrNotTrusted, "by-arn", nil},
		"the account":        {nil, "by-account", []servicerole.Option{servicerole.WithSourceAccount(account)}},
		"another account":    {servicerole.ErrNotTrusted, "by-account", []servicerole.Option{servicerole.WithSourceAccount("123456789012")}},
		"no source account":  {servicerole.ErrNotTrusted, "by-account", nil},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := c.AssumeServiceRole(ctx, roleARN(tc.role), "s1", lambda, 0, tc.opts...)
			if !errors.Is(err, tc.want) {
				t.Fatalf("got %v, want %v", err, tc.want)
			}
		})
	}

	for name, opt := range map[string]servicerole.Option{
		"a source ARN that is no ARN":        servicerole.WithSourceArn("function:one"),
		"a source account of 11 digits":      servicerole.WithSourceAccount("12345678901"),
		"a source account that is no number": servicerole.WithSourceAccount("abcdefghijkl"),
	} {
		t.Run(name, func(t *testing.T) {
			_, err := c.AssumeServiceRole(ctx, roleARN("by-arn"), "s1", lambda, 0, opt)
			var e *servicerole.Error
			if !errors.As(err, &e) || e.Code != servicerole.CodeInvalidRequest {
				t.Fatalf("got %v, want %s", err, servicerole.CodeInvalidRequest)
			}
		})
	}
}
