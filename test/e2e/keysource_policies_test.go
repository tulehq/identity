//go:build e2e

package e2e

import (
	"encoding/json"
	"slices"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"tule.dev/sigv4"
)

// canonical re-encodes a JSON document so that two documents with the same
// value compare equal as strings (encoding/json sorts object keys).
func canonical(t *testing.T, doc []byte) string {
	t.Helper()
	var v any
	requireNoErr(t, json.Unmarshal(doc, &v), "parse policy document "+string(doc))
	b, err := json.Marshal(v)
	requireNoErr(t, err, "re-encode policy document")
	return string(b)
}

// requirePolicies fails unless the principal carries exactly the documents
// in want, in any order: the design does not order them.
func requirePolicies(t *testing.T, p sigv4.Principal, want ...string) {
	t.Helper()
	got := make([]string, 0, len(p.Policies))
	for _, d := range p.Policies {
		got = append(got, canonical(t, d))
	}
	w := make([]string, 0, len(want))
	for _, d := range want {
		w = append(w, canonical(t, []byte(d)))
	}
	slices.Sort(got)
	slices.Sort(w)
	if !slices.Equal(got, w) {
		t.Fatalf("principal policies:\n got %v\nwant %v", got, w)
	}
}

// verifiedPrincipal verifies a request signed with creds through the key
// source and returns its principal.
func verifiedPrincipal(t *testing.T, srv *server, creds aws.Credentials) sigv4.Principal {
	t.Helper()
	v := verifierFor(t, keySourceFor(t, srv, rootCreds()))
	verified, err := v.Verify(signedRequest(t, creds))
	requireNoErr(t, err, "verify")
	p, ok := sigv4.PrincipalFrom(verified.Context())
	if !ok {
		t.Fatal("verified request carries no principal")
	}
	return p
}

func TestKeySourcePrincipalPolicies(t *testing.T) {
	// The design: the signing-key endpoint returns the principal's effective
	// identity policies, inline and attached managed at their default
	// versions, and the keysource client passes them into
	// sigv4.Principal.Policies.
	srv, c := rootIAM(t)
	inline := policyDoc(allow("s3:GetObject", "arn:aws:s3:::bucket/*"))
	v1 := policyDoc(allow("sqs:SendMessage", "*"))
	v2 := policyDoc(allow("sqs:ReceiveMessage", "*"))
	managed := createPolicy(t, c, "Queues", v1)
	createVersion(t, c, managed, v2, true)

	createUser(t, c, "dev")
	putUserPolicy(t, c, "dev", "objects", inline)
	attachUserPolicy(t, c, "dev", managed)
	attachUserPolicy(t, c, "dev", adminAccessARN)
	key := createKey(t, c, "dev")

	p := verifiedPrincipal(t, srv, key)
	requireEqual(t, p.Root, false, "Root")
	requirePolicies(t, p, inline, v2, adminAccessDoc)

	t.Run("follows changes", func(t *testing.T) {
		detachUserPolicy(t, c, "dev", adminAccessARN)
		requirePolicies(t, verifiedPrincipal(t, srv, key), inline, v2)
	})

	t.Run("a user with none", func(t *testing.T) {
		p := verifiedPrincipal(t, srv, userWithKey(t, c, "bare"))
		requireEqual(t, p.Root, false, "Root")
		requirePolicies(t, p)
	})
}

func TestKeySourceRootPrincipal(t *testing.T) {
	// The design: Root is set for the root key, which is never evaluated.
	srv := startServer(t, nil)
	p := verifiedPrincipal(t, srv, rootCreds())
	requireEqual(t, p.Root, true, "Root")
	requireEqual(t, p.ARN, rootARN(defaultAccountID), "ARN")
}

func TestKeySourceSessionPolicies(t *testing.T) {
	// The design: "Sessions carry their role's policies".
	srv, c := rootIAM(t)
	role := iamRoleARN(defaultAccountID, "/", "Reader")
	doc := policyDoc(allow("s3:GetObject", "*"))
	createRole(t, c, "Reader", trustDoc(rootARN(defaultAccountID)))
	putRolePolicy(t, c, "Reader", "read", doc)
	attachRolePolicy(t, c, "Reader", adminAccessARN)
	key := userWithPolicy(t, c, "dev", canAssume(role))

	out := mustAssume(t, srv, key, role, "keysource")
	p := verifiedPrincipal(t, srv, sessionCreds(out))
	requireEqual(t, p.ARN, aws.ToString(out.AssumedRoleUser.Arn), "ARN")
	requireEqual(t, p.Root, false, "Root")
	requirePolicies(t, p, doc, adminAccessDoc)
}
