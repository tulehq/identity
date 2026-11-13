//go:build e2e

package e2e

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/iam/types"
	"tule.dev/sigv4"

	"tule.dev/identity/keysource"
)

// The scope another Tule service's request is signed for: not identity's
// own, so the lookup is the other service's.
const (
	otherService = "s3"
	otherRegion  = "eu-west-1"
)

// keySourceFor returns a KeySource client for srv, authenticated with creds.
func keySourceFor(t *testing.T, srv *server, creds aws.Credentials) *keysource.Client {
	t.Helper()
	ks, err := keysource.New(keysource.Config{
		HTTPClient:      srv.Client(),
		Endpoint:        srv.URL,
		AccessKeyID:     creds.AccessKeyID,
		SecretAccessKey: creds.SecretAccessKey,
	})
	requireNoErr(t, err, "new key source")
	return ks
}

// verifierFor returns the verifier another Tule service would build over ks.
func verifierFor(t *testing.T, ks sigv4.KeySource) *sigv4.Verifier {
	t.Helper()
	v, err := sigv4.New(ks)
	requireNoErr(t, err, "new verifier")
	return v
}

// signedRequest is a request to another service, signed with creds, as that
// service receives it. It is built afresh for each verification, since the
// verifier reads the body.
func signedRequest(t *testing.T, creds aws.Credentials) *http.Request {
	t.Helper()

	body := []byte(`{"example":true}`)
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost,
		"http://service.example.test/", bytes.NewReader(body))
	requireNoErr(t, err, "build request")
	req.Header.Set("Content-Type", "application/json")

	sum := sha256.Sum256(body)
	err = v4.NewSigner().SignHTTP(t.Context(), creds, req, hex.EncodeToString(sum[:]),
		otherService, otherRegion, time.Now())
	requireNoErr(t, err, "sign request")
	return req
}

// requireKind fails unless err is a *sigv4.Error of kind.
func requireKind(t *testing.T, err error, kind sigv4.Kind) {
	t.Helper()
	var e *sigv4.Error
	if !errors.As(err, &e) {
		t.Fatalf("want *sigv4.Error %v, got %v", kind, err)
	}
	if e.Kind != kind {
		t.Fatalf("Kind = %v, want %v (%v)", e.Kind, kind, err)
	}
}

func TestKeySourceVerifiesUserKey(t *testing.T) {
	srv, c := rootIAM(t)
	key := userWithKey(t, c, "signer")
	user, err := c.GetUser(t.Context(), &iam.GetUserInput{UserName: aws.String("signer")})
	requireNoErr(t, err, "get user")

	ks := keySourceFor(t, srv, rootCreds())
	v := verifierFor(t, ks)

	t.Run("active key verifies", func(t *testing.T) {
		before := time.Now()
		verified, err := v.Verify(signedRequest(t, key))
		requireNoErr(t, err, "verify")
		p, ok := sigv4.PrincipalFrom(verified.Context())
		if !ok {
			t.Fatal("verified request carries no principal")
		}
		requireEqual(t, p.ARN, aws.ToString(user.User.Arn), "principal ARN")
		requireEqual(t, p.AccountID, defaultAccountID, "principal AccountID")
		requireEqual(t, p.AccessKeyID, key.AccessKeyID, "principal AccessKeyID")

		// The spec: the endpoint records each key's last use, with the
		// service and region of the lookup's scope.
		out := lastUsed(t, c, key.AccessKeyID)
		requireEqual(t, aws.ToString(out.AccessKeyLastUsed.ServiceName), otherService,
			"ServiceName")
		requireEqual(t, aws.ToString(out.AccessKeyLastUsed.Region), otherRegion, "Region")
		requireRecent(t, out.AccessKeyLastUsed.LastUsedDate, before, time.Now(),
			"LastUsedDate")
	})

	t.Run("derived key, not the secret", func(t *testing.T) {
		date := time.Now().UTC().Format("20060102")
		k, err := ks.SigningKey(t.Context(), sigv4.Scope{
			AccessKeyID: key.AccessKeyID,
			Date:        date,
			Region:      otherRegion,
			Service:     otherService,
		})
		requireNoErr(t, err, "signing key")
		want := sigv4.DeriveSigningKey(key.SecretAccessKey, date, otherRegion, otherService)
		if !bytes.Equal(k.Signing, want) {
			t.Fatal("signing key is not the one derived from the key's secret for the scope")
		}
		requireEqual(t, k.Principal.ARN, aws.ToString(user.User.Arn), "principal ARN")
	})

	testKeySourceKeyStates(t, c, v, key)
}

// testKeySourceKeyStates checks that the key source follows the key's status.
func testKeySourceKeyStates(t *testing.T, c *iam.Client, v *sigv4.Verifier, key aws.Credentials) {
	// The client holds no cache, so the same request is refused once the
	// key is inactive: as an unknown key, the way AWS refuses an inactive
	// one, and distinguishably as ErrInactiveAccessKey.
	t.Run("inactive key is refused", func(t *testing.T) {
		setKeyStatus(t, c, "signer", key.AccessKeyID, types.StatusTypeInactive)
		_, err := v.Verify(signedRequest(t, key))
		requireKind(t, err, sigv4.KindUnknownAccessKey)
		if !errors.Is(err, keysource.ErrInactiveAccessKey) {
			t.Fatalf("error %v is not ErrInactiveAccessKey", err)
		}
		if !errors.Is(err, sigv4.ErrUnknownAccessKey) {
			t.Fatalf("error %v does not wrap sigv4.ErrUnknownAccessKey", err)
		}
	})

	t.Run("reactivated key verifies", func(t *testing.T) {
		setKeyStatus(t, c, "signer", key.AccessKeyID, types.StatusTypeActive)
		_, err := v.Verify(signedRequest(t, key))
		requireNoErr(t, err, "verify after reactivating")
	})

	t.Run("deleted key is unknown", func(t *testing.T) {
		_, err := c.DeleteAccessKey(t.Context(), &iam.DeleteAccessKeyInput{
			UserName: aws.String("signer"), AccessKeyId: aws.String(key.AccessKeyID),
		})
		requireNoErr(t, err, "delete access key")
		_, err = v.Verify(signedRequest(t, key))
		requireKind(t, err, sigv4.KindUnknownAccessKey)
		if errors.Is(err, keysource.ErrInactiveAccessKey) {
			t.Fatal("a deleted key is reported as inactive")
		}
	})

	t.Run("wrong secret is a signature mismatch", func(t *testing.T) {
		other := createKey(t, c, "signer")
		other.SecretAccessKey = "wrong"
		_, err := v.Verify(signedRequest(t, other))
		requireKind(t, err, sigv4.KindSignatureMismatch)
	})
}

func TestKeySourceVerifiesRootKey(t *testing.T) {
	srv := startServer(t, nil)
	v := verifierFor(t, keySourceFor(t, srv, rootCreds()))

	verified, err := v.Verify(signedRequest(t, rootCreds()))
	requireNoErr(t, err, "verify")
	p, _ := sigv4.PrincipalFrom(verified.Context())
	requireEqual(t, p.ARN, "arn:aws:iam::"+defaultAccountID+":root", "principal ARN")
	requireEqual(t, p.AccountID, defaultAccountID, "principal AccountID")
}

func TestKeySourceEndpointNeedsRootKey(t *testing.T) {
	// The spec: the endpoint is authenticated with SigV4 using the root key.
	// Assumption: another principal's key, even an active one, is refused,
	// since the endpoint hands out signing keys; keysource documents 403 for
	// the endpoint's own authentication failures.
	srv, c := rootIAM(t)
	key := userWithKey(t, c, "dev")

	for name, creds := range map[string]aws.Credentials{
		"wrong secret": {AccessKeyID: rootKeyID, SecretAccessKey: "wrong"},
		"user key":     key,
	} {
		t.Run(name, func(t *testing.T) {
			ks := keySourceFor(t, srv, creds)
			_, err := ks.SigningKey(t.Context(), sigv4.Scope{
				AccessKeyID: key.AccessKeyID,
				Date:        time.Now().UTC().Format("20060102"),
				Region:      otherRegion,
				Service:     otherService,
			})
			var e *keysource.Error
			if !errors.As(err, &e) {
				t.Fatalf("want *keysource.Error, got %v", err)
			}
			requireEqual(t, e.Status, http.StatusForbidden, "status")

			// A verifier reports it as a failed lookup, not a refused key.
			_, err = verifierFor(t, ks).Verify(signedRequest(t, key))
			requireKind(t, err, sigv4.KindKeyLookupFailed)
		})
	}
}

// testKeySourceSession checks a role session's key through the key source:
// its principal is the session, and its token is checked.
func testKeySourceSession(t *testing.T, f orgFixture) {
	out := assume(t, f.srv, f.member, "verified", nil)
	sess := sessionCreds(out)
	v := verifierFor(t, keySourceFor(t, f.srv, rootCreds()))

	verified, err := v.Verify(signedRequest(t, sess))
	requireNoErr(t, err, "verify the session's request")
	p, _ := sigv4.PrincipalFrom(verified.Context())
	requireEqual(t, p.ARN, aws.ToString(out.AssumedRoleUser.Arn), "principal ARN")
	requireEqual(t, p.AccountID, f.member, "principal AccountID")
	// A session in a member account names its role there.
	requireEqual(t, p.PrincipalARN, roleARN(f.member), "principal PrincipalARN")
	requireMatch(t, sessionUserIDPattern("verified"), p.UserID, "principal UserID")
	requireEqual(t, p.UserID, aws.ToString(out.AssumedRoleUser.AssumedRoleId), "principal UserID")
	requireEqual(t, p.Type, sigv4.PrincipalTypeAssumedRole, "principal Type")

	_, err = v.Verify(signedRequest(t, withToken(sess, tamper(sess.SessionToken))))
	requireKind(t, err, sigv4.KindInvalidSessionToken)

	// sigv4: a temporary key sent without its token is an unknown key.
	_, err = v.Verify(signedRequest(t, withToken(sess, "")))
	requireKind(t, err, sigv4.KindUnknownAccessKey)
}
