//go:build e2e

package e2e

import (
	"bytes"
	"context"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	awsorg "github.com/aws/aws-sdk-go-v2/service/organizations"
	orgtypes "github.com/aws/aws-sdk-go-v2/service/organizations/types"
)

// accountsDirEnv names the accounts checkout to build, for a layout where it
// is not identity's sibling.
const accountsDirEnv = "TULE_E2E_ACCOUNTS_DIR"

// syncBuffer collects a process's output, safe to write from the process's
// copying goroutines and read from the test.
type syncBuffer struct {
	buf bytes.Buffer
	mu  sync.Mutex
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p) //nolint:wrapcheck // bytes.Buffer.Write never fails
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// startAccounts builds the accounts service from its checkout, runs it on a
// free port with a fresh store and the same root key identity has, and
// returns its URL. The process is stopped when the test ends.
func startAccounts(t *testing.T) string {
	t.Helper()

	bin := buildAccounts(t)
	port := freePort(t)
	dir := t.TempDir()

	cmd := exec.Command(bin) //nolint:gosec // G204: the binary this test just built
	cmd.Dir = dir
	cmd.Env = append(envWithoutTule(),
		"TULE_GasEnv=testing",
		"TULE_Server_Port="+strconv.Itoa(port),
		"TULE_Store_Path="+filepath.Join(dir, "accounts.db"),
		"TULE_Auth_AccessKeyID="+rootKeyID,
		"TULE_Auth_SecretAccessKey="+rootSecret,
	)
	out := &syncBuffer{}
	cmd.Stdout = out
	cmd.Stderr = out
	if err := cmd.Start(); err != nil {
		t.Fatalf("start accounts: %v", err)
	}

	exited := make(chan error, 1)
	go func() { exited <- cmd.Wait() }()
	t.Cleanup(func() { stopProcess(t, cmd, exited, out) })

	url := "http://127.0.0.1:" + strconv.Itoa(port)
	waitReady(t, url, exited, out)
	return url
}

// buildAccounts builds the accounts binary into a temporary directory.
func buildAccounts(t *testing.T) string {
	t.Helper()

	// The test runs in identity/test/e2e; by default accounts is identity's
	// sibling. CI sets the directory. A missing checkout fails the test, so
	// the cross-service test is never silently left out.
	src, from := os.Getenv(accountsDirEnv), accountsDirEnv
	if src == "" {
		src, from = filepath.Join("..", "..", "..", "accounts"), "the default sibling path"
	}
	src, err := filepath.Abs(src)
	requireNoErr(t, err, "accounts directory")
	//nolint:gosec // G703: the checkout the test is told to build
	if _, err = os.Stat(filepath.Join(src, "go.mod")); err != nil {
		t.Fatalf("no accounts checkout at %s (from %s); set %s to an accounts checkout: %v",
			src, from, accountsDirEnv, err)
	}

	bin := filepath.Join(t.TempDir(), "tule-accounts")
	//nolint:gosec // G204: go build of the checkout into this test's directory
	build := exec.CommandContext(t.Context(), "go", "build", "-o", bin, "./cmd")
	build.Dir = src
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build accounts: %v\n%s", err, out)
	}
	return bin
}

// envWithoutTule is this process's environment minus the TULE_ variables the
// tests set for identity, so the accounts process gets only its own.
func envWithoutTule() []string {
	var env []string
	for _, kv := range os.Environ() {
		if !strings.HasPrefix(kv, "TULE_") {
			env = append(env, kv)
		}
	}
	return env
}

func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	requireNoErr(t, err, "find a free port")
	port := l.Addr().(*net.TCPAddr).Port
	requireNoErr(t, l.Close(), "release the free port")
	return port
}

// waitReady polls the service's readiness probe until it answers 200.
func waitReady(t *testing.T, url string, exited <-chan error, out *syncBuffer) {
	t.Helper()

	client := &http.Client{Timeout: time.Second}
	deadline := time.Now().Add(clientTimeout)
	for time.Now().Before(deadline) {
		select {
		case err := <-exited:
			t.Fatalf("accounts exited before it was ready: %v\n%s", err, out.String())
		default:
		}
		req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, url+"/_ready", nil)
		requireNoErr(t, err, "build readiness request")
		if res, err := client.Do(req); err == nil {
			_ = res.Body.Close()
			if res.StatusCode == http.StatusOK {
				return
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("accounts was not ready within %v\n%s", clientTimeout, out.String())
}

// stopProcess interrupts the process, as a signal stops the service, and
// kills it if it does not exit in time.
func stopProcess(t *testing.T, cmd *exec.Cmd, exited <-chan error, out *syncBuffer) {
	t.Helper()

	_ = cmd.Process.Signal(os.Interrupt)
	select {
	case err := <-exited:
		if err != nil {
			t.Logf("accounts exited: %v", err)
		}
	case <-time.After(clientTimeout):
		_ = cmd.Process.Kill()
		err := <-exited
		t.Errorf("accounts did not stop on interrupt (%v)\n%s", err, out.String())
	}
}

// orgClient returns an Organizations client for the accounts service, signed
// with the root key.
func orgClient(url string) *awsorg.Client {
	return awsorg.New(awsorg.Options{
		Region:           signingRegion,
		BaseEndpoint:     aws.String(url),
		Credentials:      credentials.StaticCredentialsProvider{Value: rootCreds()},
		HTTPClient:       &http.Client{Timeout: clientTimeout},
		RetryMaxAttempts: 1,
	})
}

// createOrgAccount creates a member account and returns its ID.
func createOrgAccount(t *testing.T, c *awsorg.Client, name, email string) string {
	t.Helper()

	out, err := c.CreateAccount(t.Context(), &awsorg.CreateAccountInput{
		AccountName: aws.String(name),
		Email:       aws.String(email),
	})
	requireNoErr(t, err, "create account "+name)
	st := out.CreateAccountStatus
	if st == nil || st.State != orgtypes.CreateAccountStateSucceeded {
		t.Fatalf("create account %s: %+v", name, st)
	}
	return aws.ToString(st.AccountId)
}

// orgFixture is an identity server pointed at a running accounts service
// with an organization holding an active and a closed member account.
type orgFixture struct {
	srv    *server
	member string
	closed string
}

func newOrgFixture(t *testing.T) orgFixture {
	t.Helper()

	// accounts first: startServer sets TULE_ variables for identity in this
	// process, which accounts must not see.
	url := startAccounts(t)
	oc := orgClient(url)
	_, err := oc.CreateOrganization(t.Context(), &awsorg.CreateOrganizationInput{})
	requireNoErr(t, err, "create organization")

	f := orgFixture{
		member: createOrgAccount(t, oc, "Member", "member@example.com"),
		closed: createOrgAccount(t, oc, "Closed", "closed@example.com"),
	}
	_, err = oc.CloseAccount(context.Background(), &awsorg.CloseAccountInput{
		AccountId: aws.String(f.closed),
	})
	requireNoErr(t, err, "close account")

	f.srv = startServer(t, map[string]string{"TULE_Identity_AccountsEndpoint": url})
	return f
}
