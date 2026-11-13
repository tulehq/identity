package trustdoc

import (
	"strings"
	"testing"

	"tule.dev/policy"

	"tule.dev/identity/internal/contracts"
)

func TestRewritePrincipalsKeepsTheDocument(t *testing.T) {
	doc := `{"Version":"2012-10-17","Statement":[{"Sid":"one","Effect":"Allow",` +
		`"Principal":{"AWS":["arn:aws:iam::123456789012:user/a","123456789012"]},` +
		`"Action":"sts:AssumeRole","Condition":{"ArnEquals":` +
		`{"aws:PrincipalArn":"arn:aws:iam::123456789012:user/a"}}},` +
		`{"Effect":"Allow","Principal":"*","Action":"sts:AssumeRole"}]}`

	got, changed, err := RewritePrincipals(doc, func(v string) string { return v })
	if err != nil || changed || got != doc {
		t.Fatalf("identity rewrite = %s, %v, %v", got, changed, err)
	}

	// Only the Principal's AWS value changes: the condition keeps the ARN,
	// as AWS does not bind condition keys, and members keep their order.
	got, changed, err = RewritePrincipals(doc, func(v string) string {
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
	got, err := BindablePrincipals(doc)
	want := "arn:aws:iam::123456789012:user/a arn:aws:iam::123456789012:role/p/r"
	if err != nil || strings.Join(got, " ") != want {
		t.Fatalf("bindable = %v, %v; want %s", got, err, want)
	}
}

func TestForCallerBindsPrincipalsToTheCaller(t *testing.T) {
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
		doc, err := ForCaller(role, caller)
		if err != nil || !strings.Contains(doc, want) {
			t.Errorf("trust for %q = %s, %v; want %s", caller, doc, err, want)
		}
		// Every rewritten policy parses, and only the bound caller is
		// trusted by it.
		p, err := policy.ParseTrust([]byte(doc))
		if err != nil {
			t.Fatalf("trust for %q does not parse: %v", caller, err)
		}
		got := policy.TrustMatch(p, "123456789012", "sts:AssumeRole", arn, nil).Decision
		if wantAllow := caller == "AIDAOLD"; (got == policy.Allow) != wantAllow {
			t.Errorf("trust for %q decides %s for %s", caller, got, arn)
		}
	}
	role.TrustBindings = nil
	doc, err := ForCaller(role, "AIDAOLD")
	if err != nil || strings.Contains(doc, `"`+arn+`"`) {
		t.Errorf("an unbound ARN = %s, %v; want it to name no one", doc, err)
	}
	if _, err = policy.ParseTrust([]byte(doc)); err != nil {
		t.Errorf("the rewritten trust policy does not parse: %v", err)
	}
}
