package query

import (
	"encoding/json"
	"errors"
	"strings"
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

func TestRewritePrincipalsKeepsTheDocument(t *testing.T) {
	doc := `{"Version":"2012-10-17","Statement":[{"Sid":"one","Effect":"Allow",` +
		`"Principal":{"AWS":["arn:aws:iam::123456789012:user/a","123456789012"]},` +
		`"Action":"sts:AssumeRole","Condition":{"ArnEquals":` +
		`{"aws:PrincipalArn":"arn:aws:iam::123456789012:user/a"}}},` +
		`{"Effect":"Allow","Principal":"*","Action":"sts:AssumeRole"}]}`

	got, changed, err := rewritePrincipals(doc, func(v string) string { return v })
	if err != nil || changed || got != doc {
		t.Fatalf("identity rewrite = %s, %v, %v", got, changed, err)
	}

	// Only the Principal's AWS value changes: the condition keeps the ARN,
	// as AWS does not bind condition keys, and members keep their order.
	got, changed, err = rewritePrincipals(doc, func(v string) string {
		if v == "arn:aws:iam::123456789012:user/a" {
			return "AIDAEXAMPLE"
		}
		return v
	})
	want := strings.Replace(
		doc,
		`"AWS":["arn:aws:iam::123456789012:user/a"`,
		`"AWS":["AIDAEXAMPLE"`,
		1,
	)
	if err != nil || !changed || got != want {
		t.Fatalf("rewrite = %s, %v, %v; want %s", got, changed, err, want)
	}
}

func TestBindablePrincipals(t *testing.T) {
	doc := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":[` +
		`"arn:aws:iam::123456789012:user/a","123456789012","arn:aws:iam::123456789012:root",` +
		`"arn:aws:iam::123456789012:role/p/r","arn:aws:sts::123456789012:assumed-role/r/s",` +
		`"arn:aws:iam::123456789012:user/a"]},"Action":"sts:AssumeRole"}]}`
	got, err := bindablePrincipals(doc)
	want := "arn:aws:iam::123456789012:user/a arn:aws:iam::123456789012:role/p/r"
	if err != nil || strings.Join(got, " ") != want {
		t.Fatalf("bindable = %v, %v; want %s", got, err, want)
	}
}

func TestTrustForBindsPrincipalsToTheCaller(t *testing.T) {
	const arn = "arn:aws:iam::123456789012:user/a"
	role := &contracts.Role{
		TrustPolicy: `{"Version":"2012-10-17","Statement":{"Effect":"Allow",` +
			`"Principal":{"AWS":"` + arn + `"},"Action":"sts:AssumeRole"}}`,
		TrustBindings: []contracts.TrustBinding{{ARN: arn, PrincipalID: "AIDAOLD", Current: true}},
	}
	for caller, want := range map[string]string{
		"AIDAOLD": `"AWS":"` + arn + `"`,
		"AIDANEW": `"AWS":"arn:aws:iam::123456789012:unbound/AIDAOLD"`,
		"":        `"AWS":"arn:aws:iam::123456789012:unbound/AIDAOLD"`,
	} {
		doc, err := trustFor(role, caller)
		if err != nil || !strings.Contains(doc, want) {
			t.Errorf("trust for %q = %s, %v; want %s", caller, doc, err, want)
		}
		// Every rewritten policy parses, and only the bound caller is
		// trusted by it.
		p, err := parseDocument(doc, trustDocument)
		if err != nil {
			t.Fatalf("trust for %q does not parse: %v", caller, err)
		}
		got := policy.TrustMatch(p, "123456789012", "sts:AssumeRole", arn, nil).Decision
		if wantAllow := caller == "AIDAOLD"; (got == policy.Allow) != wantAllow {
			t.Errorf("trust for %q decides %s for %s", caller, got, arn)
		}
	}
	role.TrustBindings = nil
	doc, err := trustFor(role, "AIDAOLD")
	if err != nil || strings.Contains(doc, `"`+arn+`"`) {
		t.Errorf("an unbound ARN = %s, %v; want it to name no one", doc, err)
	}
	if _, err = parseDocument(doc, trustDocument); err != nil {
		t.Errorf("the rewritten trust policy does not parse: %v", err)
	}
}
