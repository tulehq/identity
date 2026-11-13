package query

import (
	"encoding/json"
	"errors"
	"testing"

	"tule.dev/policy"

	"tule.dev/identity/internal/contracts"
	"tule.dev/identity/internal/queryapi"
)

func TestEveryRoutedOperationHasAnAuthorizationEntry(t *testing.T) {
	m := NewModule(nil, nil, nil)
	for svc, ops := range m.handlers {
		for op := range ops {
			entry, ok := operations[svc][op]
			if !ok {
				t.Errorf("%s %s is routed but has no authorization entry", svc.Name, op)
				continue
			}
			// The action is the operation's own name in the service's
			// namespace, as the reference names every action here.
			if entry.action != svc.Name+":"+op {
				t.Errorf("%s %s is evaluated as %s", svc.Name, op, entry.action)
			}
			if !entry.always && entry.resource == nil {
				t.Errorf("%s %s has no resource", svc.Name, op)
			}
		}
	}
}

func TestEveryAuthorizationEntryIsRouted(t *testing.T) {
	m := NewModule(nil, nil, nil)
	for svc, ops := range operations {
		for op, entry := range ops {
			if _, ok := m.handlers[svc][op]; !ok {
				t.Errorf("%s %s has an authorization entry but is not routed", svc.Name, op)
			}
			// Only GetCallerIdentity is allowed to everyone.
			if entry.always != (svc == queryapi.STS && op == "GetCallerIdentity") {
				t.Errorf("%s %s always = %v", svc.Name, op, entry.always)
			}
		}
	}
}

func TestTheResourcesOfNewEntities(t *testing.T) {
	caller := &contracts.Principal{AccountID: "123456789012"}
	for _, tc := range []struct {
		resource func(*Module, *call) (string, error)
		params   queryapi.Params
		want     string
	}{
		{
			func(m *Module, c *call) (string, error) { return newUserResource(m, nil, c) },
			queryapi.Params{"UserName": {"dev"}, "Path": {"/ops/"}},
			"arn:aws:iam::123456789012:user/ops/dev",
		},
		{
			func(m *Module, c *call) (string, error) { return newRoleResource(m, nil, c) },
			queryapi.Params{"RoleName": {"app"}},
			"arn:aws:iam::123456789012:role/app",
		},
		{
			func(m *Module, c *call) (string, error) { return newPolicyResource(m, nil, c) },
			queryapi.Params{"PolicyName": {"p"}, "Path": {"/a/"}},
			"arn:aws:iam::123456789012:policy/a/p",
		},
		{
			func(m *Module, c *call) (string, error) { return anyResource(m, nil, c) },
			nil, "*",
		},
	} {
		got, err := tc.resource(nil, &call{params: tc.params, caller: caller})
		if err != nil || got != tc.want {
			t.Errorf("resource = %q, %v; want %q", got, err, tc.want)
		}
	}
}

func TestDenialsFollowAWSMessages(t *testing.T) {
	c := &call{caller: &contracts.Principal{ARN: "arn:aws:iam::123456789012:user/dev"}}
	base := "User: arn:aws:iam::123456789012:user/dev is not authorized to perform: " +
		"iam:ListUsers on resource: *"
	for result, want := range map[policy.Decision]string{
		policy.ImplicitDeny: base + " because no identity-based policy allows the iam:ListUsers action",
		policy.ExplicitDeny: base + " with an explicit deny in an identity-based policy",
	} {
		err := decision{action: "iam:ListUsers", resource: "*", result: result}.err(c)
		var apiErr *queryapi.Error
		if !errors.As(err, &apiErr) || apiErr.Code != queryapi.CodeAccessDenied ||
			apiErr.Message != want {
			t.Errorf("%s = %v, want AccessDenied %q", result, err, want)
		}
	}
	if err := (decision{result: policy.Allow}).err(c); err != nil {
		t.Errorf("Allow = %v", err)
	}
}

// callWith returns a call whose principal carries the documents.
func callWith(kind contracts.PrincipalKind, arn string, docs ...string) *call {
	c := &call{caller: &contracts.Principal{
		Kind: kind, ARN: arn, UserName: "alice",
		AccountID: "123456789012",
	}}
	for _, d := range docs {
		c.signer.Policies = append(c.signer.Policies, json.RawMessage(d))
	}
	return c
}

func TestEvaluateSubstitutesVariables(t *testing.T) {
	// The same document, from whichever source, is evaluated with the
	// request's keys, so ${aws:username} names the caller.
	doc := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow",` +
		`"Action":"iam:ListAccessKeys","Resource":"arn:aws:iam::123456789012:user/${aws:username}"}]}`
	c := callWith(contracts.PrincipalUser, "arn:aws:iam::123456789012:user/alice", doc)
	keys := map[string][]string{"aws:username": {"alice"}}
	for resource, want := range map[string]policy.Decision{
		"arn:aws:iam::123456789012:user/alice": policy.Allow,
		"arn:aws:iam::123456789012:user/bob":   policy.ImplicitDeny,
	} {
		got, err := evaluate(c, "iam:ListAccessKeys", resource, keys)
		if err != nil || got != want {
			t.Errorf("%s = %s, %v; want %s", resource, got, err, want)
		}
	}
}

func TestDocumentsAreParsedByKind(t *testing.T) {
	withPrincipal := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":"*",` +
		`"Action":"sts:AssumeRole"}]}`
	without := `{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"iam:*",` +
		`"Resource":"*"}}`
	for _, tc := range []struct {
		doc  string
		kind documentKind
		ok   bool
	}{
		{withPrincipal, trustDocument, true},
		{withPrincipal, identityDocument, false},
		{without, identityDocument, true},
		{without, trustDocument, false},
	} {
		_, err := parseDocument(tc.doc, tc.kind)
		var pe *policy.ParseError
		if (err == nil) != tc.ok || (err != nil && !errors.As(err, &pe)) {
			t.Errorf("parseDocument(%s, %d) = %v", tc.doc, tc.kind, err)
		}
	}
}
