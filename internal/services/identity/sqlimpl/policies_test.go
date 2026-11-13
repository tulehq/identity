package sqlimpl

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"tule.dev/identity/internal/contracts"
)

// doc is an identity policy allowing action on every resource.
func doc(action string) string {
	return `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"` + action +
		`","Resource":"*"}]}`
}

func createPolicy(t *testing.T, s *Service, account, name string) *contracts.ManagedPolicy {
	t.Helper()
	p, err := s.CreatePolicy(context.Background(), contracts.CreatePolicyInput{
		AccountID: account, Name: name, Path: "/", Document: doc("iam:GetUser"),
	})
	requireNoErr(t, err, "create policy "+name)
	return p
}

// createUser creates the user dev in the account.
func createUser(t *testing.T, s *Service, account string) {
	t.Helper()
	_, err := s.CreateUser(context.Background(), account, "dev", "/", nil)
	requireNoErr(t, err, "create user dev")
}

// createRole creates the role app in the member account.
func createRole(t *testing.T, s *Service) *contracts.Role {
	t.Helper()
	r, err := s.CreateRole(context.Background(), contracts.CreateRoleInput{
		AccountID: member, Name: "app", Path: "/", MaxSessionDuration: 3600,
		TrustPolicy: contracts.OrganizationTrustPolicy(member),
	})
	requireNoErr(t, err, "create role app")
	return r
}

// user is the user dev of the account.
func user(account string) contracts.Entity {
	return contracts.Entity{Kind: contracts.EntityUser, AccountID: account, Name: "dev"}
}

// role is a role of the member account.
func role(name string) contracts.Entity {
	return contracts.Entity{Kind: contracts.EntityRole, AccountID: member, Name: name}
}

func TestManagedPolicies(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)
	p := createPolicy(t, s, management, "Readers")
	check(t, p.ARN == "arn:aws:iam::000000000000:policy/Readers" &&
		p.DefaultVersionID == "v1" && strings.HasPrefix(p.ID, "ANPA"), "policy = %+v", p)

	// Names are unique in the account without regard to case, and per
	// account.
	_, err := s.CreatePolicy(ctx, contracts.CreatePolicyInput{
		AccountID: management, Name: "readers", Path: "/", Document: doc("iam:GetUser"),
	})
	requireErr(t, err, contracts.ErrPolicyExists)
	createPolicy(t, s, member, "Readers")

	// Another account's policy is not found.
	_, err = s.GetPolicy(ctx, member, p.ARN)
	requireErr(t, err, contracts.ErrPolicyNotFound)

	// Up to five versions; the oldest is v1.
	for i := 2; i <= contracts.MaxPolicyVersions; i++ {
		v, vErr := s.CreatePolicyVersion(ctx, management, p.ARN, doc("iam:ListUsers"), i == 3)
		requireNoErr(t, vErr, "create version")
		check(t, v.VersionID == fmt.Sprintf("v%d", i), "version = %+v", v)
	}
	_, err = s.CreatePolicyVersion(ctx, management, p.ARN, doc("iam:ListUsers"), false)
	requireErr(t, err, contracts.ErrPolicyVersionLimitExceeded)

	got, err := s.GetPolicy(ctx, management, p.ARN)
	requireNoErr(t, err, "get policy")
	check(t, got.DefaultVersionID == "v3", "default = %s", got.DefaultVersionID)

	// The default version cannot be deleted; another can, and its ID is
	// not reused.
	requireErr(t, s.DeletePolicyVersion(ctx, management, p.ARN, "v3"),
		contracts.ErrDefaultPolicyVersion)
	requireNoErr(t, s.DeletePolicyVersion(ctx, management, p.ARN, "v5"), "delete v5")
	v, err := s.CreatePolicyVersion(ctx, management, p.ARN, doc("iam:ListUsers"), false)
	requireNoErr(t, err, "create after delete")
	check(t, v.VersionID == "v6", "version after delete = %s", v.VersionID)

	page, err := s.ListPolicyVersions(ctx, contracts.ListPolicyVersionsInput{
		AccountID: management, PolicyARN: p.ARN, MaxItems: 2,
	})
	requireNoErr(t, err, "list versions")
	check(t, len(page.Items) == 2 && page.Items[0].VersionID == "v6" && page.Marker != "",
		"first page = %+v", page)

	// A policy with versions besides its default is not deleted.
	requireErr(t, s.DeletePolicy(ctx, management, p.ARN), contracts.ErrPolicyHasVersions)
	requireNoErr(t, s.SetDefaultPolicyVersion(ctx, management, p.ARN, "v1"), "set default")
	requireErr(t, s.SetDefaultPolicyVersion(ctx, management, p.ARN, "v9"),
		contracts.ErrPolicyVersionNotFound)
	for _, id := range []string{"v2", "v3", "v4", "v6"} {
		requireNoErr(t, s.DeletePolicyVersion(ctx, management, p.ARN, id), "delete "+id)
	}

	// Nor is an attached one.
	createUser(t, s, management)
	requireNoErr(t, s.AttachPolicy(ctx, user(management), p.ARN), "attach")
	requireErr(t, s.DeletePolicy(ctx, management, p.ARN), contracts.ErrPolicyAttached)
	requireNoErr(t, s.DetachPolicy(ctx, user(management), p.ARN), "detach")
	requireNoErr(t, s.DeletePolicy(ctx, management, p.ARN), "delete policy")
	_, err = s.GetPolicy(ctx, management, p.ARN)
	requireErr(t, err, contracts.ErrPolicyNotFound)
}

func TestAWSManagedPolicies(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)
	admin, err := s.GetPolicy(ctx, member, contracts.AdministratorAccessARN)
	requireNoErr(t, err, "get AdministratorAccess")
	check(t, admin.AccountID == contracts.AWSAccount && admin.DefaultVersionID == "v1" &&
		admin.AttachmentCount == 0, "AdministratorAccess = %+v", admin)

	for name, err := range map[string]error{
		"delete":         s.DeletePolicy(ctx, member, admin.ARN),
		"delete version": s.DeletePolicyVersion(ctx, member, admin.ARN, "v1"),
		"set default":    s.SetDefaultPolicyVersion(ctx, member, admin.ARN, "v1"),
	} {
		check(t, err != nil && strings.Contains(err.Error(), contracts.ErrAWSManagedPolicy.Error()),
			"%s = %v", name, err)
	}

	// The attachment count is the asking account's.
	createUser(t, s, member)
	requireNoErr(t, s.AttachPolicy(ctx, user(member), admin.ARN), "attach")
	for account, want := range map[string]int{member: 1, management: 0} {
		got, gErr := s.GetPolicy(ctx, account, admin.ARN)
		requireNoErr(t, gErr, "get AdministratorAccess")
		check(t, got.AttachmentCount == want, "%s count = %d", account, got.AttachmentCount)
	}
}

func TestListPolicies(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)
	for _, n := range []string{"b", "A", "c"} {
		createPolicy(t, s, member, n)
	}
	createPolicy(t, s, management, "other")
	createUser(t, s, member)
	requireNoErr(t, s.AttachPolicy(ctx, user(member),
		contracts.PolicyARN(member, "/", "b")), "attach")

	names := func(in contracts.ListPoliciesInput) []string {
		t.Helper()
		in.AccountID, in.PathPrefix = member, "/"
		if in.MaxItems == 0 {
			in.MaxItems = 100
		}
		var out []string
		for {
			page, err := s.ListPolicies(ctx, in)
			requireNoErr(t, err, "list policies")
			for _, p := range page.Items {
				out = append(out, p.Name)
			}
			if page.Marker == "" {
				return out
			}
			in.Marker = page.Marker
		}
	}
	for scope, want := range map[string]string{
		contracts.PolicyScopeAll:   "A AdministratorAccess b c",
		contracts.PolicyScopeLocal: "A b c",
		contracts.PolicyScopeAWS:   "AdministratorAccess",
	} {
		got := strings.Join(names(contracts.ListPoliciesInput{Scope: scope, MaxItems: 1}), " ")
		check(t, got == want, "%s = %q, want %q", scope, got, want)
	}
	got := names(contracts.ListPoliciesInput{Scope: contracts.PolicyScopeAll, OnlyAttached: true})
	check(t, strings.Join(got, " ") == "b", "only attached = %v", got)
}

func TestAttachedPolicyLimits(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)
	createUser(t, s, member)
	createRole(t, s)
	for kind, e := range map[int]contracts.Entity{
		contracts.MaxManagedPoliciesPerUser: user(member),
		contracts.MaxManagedPoliciesPerRole: role("app"),
	} {
		for i := range kind {
			p := createPolicy(t, s, member, fmt.Sprintf("%s-%d", e.Kind, i))
			requireNoErr(t, s.AttachPolicy(ctx, e, p.ARN), "attach")
			// Attaching it again changes nothing.
			requireNoErr(t, s.AttachPolicy(ctx, e, p.ARN), "attach again")
		}
		p := createPolicy(t, s, member, string(e.Kind)+"-over")
		requireErr(t, s.AttachPolicy(ctx, e, p.ARN), contracts.ErrAttachedPolicyLimitExceeded)
		requireErr(t, s.DetachPolicy(ctx, e, p.ARN), contracts.ErrPolicyNotAttached)
	}
}

func TestInlinePolicies(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)
	createUser(t, s, member)
	createRole(t, s)

	// The aggregate size, white space excluded, is bounded per kind; a
	// policy put again replaces its old size.
	for e, limit := range map[contracts.Entity]int{
		user(member): contracts.MaxUserInlinePolicySize,
		role("app"):  contracts.MaxRoleInlinePolicySize,
	} {
		half := sized(limit / 2)
		requireNoErr(t, s.PutInlinePolicy(ctx, e, "one", half), "put one")
		requireNoErr(t, s.PutInlinePolicy(ctx, e, "one", half+"   "), "put one again")
		requireNoErr(t, s.PutInlinePolicy(ctx, e, "two", sized(limit-limit/2)), "put two")
		requireErr(t, s.PutInlinePolicy(ctx, e, "three", doc("iam:GetUser")),
			contracts.ErrInlinePolicySizeExceeded)

		page, err := s.ListInlinePolicies(ctx, contracts.ListInlinePoliciesInput{
			Entity: e, MaxItems: 1,
		})
		requireNoErr(t, err, "list inline")
		check(t, len(page.Items) == 1 && page.Items[0] == "one" && page.Marker != "",
			"page = %+v", page)
		got, err := s.GetInlinePolicy(ctx, e, "one")
		requireNoErr(t, err, "get inline")
		check(t, got.Document == half+"   ", "document = %q", got.Document)
		requireNoErr(t, s.DeleteInlinePolicy(ctx, e, "two"), "delete inline")
		requireErr(t, s.DeleteInlinePolicy(ctx, e, "two"), contracts.ErrInlinePolicyNotFound)
	}
}

// sized is a policy document of exactly n characters, white space excluded.
func sized(n int) string {
	d := doc("iam:GetUser")
	pad := n - contracts.PolicySize(d)
	return strings.Replace(
		d,
		`"2012-10-17"`,
		`"2012-10-17","Id":"`+strings.Repeat("x", pad-len(`,"Id":""`))+`"`,
		1,
	)
}

func TestDeletingAnEntityWithPolicies(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)
	createUser(t, s, member)
	createRole(t, s)
	p := createPolicy(t, s, member, "p")

	for _, tc := range []struct {
		del func() error
		e   contracts.Entity
	}{
		{func() error { return s.DeleteUser(ctx, member, "dev") }, user(member)},
		{func() error { return s.DeleteRole(ctx, member, "app") }, role("app")},
	} {
		requireNoErr(t, s.AttachPolicy(ctx, tc.e, p.ARN), "attach")
		requireNoErr(t, s.PutInlinePolicy(ctx, tc.e, "inline", doc("iam:GetUser")), "put")
		requireErr(t, tc.del(), contracts.ErrHasAttachedPolicies)
		requireNoErr(t, s.DetachPolicy(ctx, tc.e, p.ARN), "detach")
		requireErr(t, tc.del(), contracts.ErrHasInlinePolicies)
		requireNoErr(t, s.DeleteInlinePolicy(ctx, tc.e, "inline"), "delete inline")
		requireNoErr(t, tc.del(), "delete")
	}
	_, err := s.GetRole(ctx, member, "app")
	requireErr(t, err, contracts.ErrRoleNotFound)
}

func TestRoles(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)
	r, err := s.CreateRole(ctx, contracts.CreateRoleInput{
		AccountID: member, Name: "App", Path: "/svc/", MaxSessionDuration: 3600,
		TrustPolicy: contracts.OrganizationTrustPolicy(management), Description: "the app",
		Tags: []contracts.Tag{{Key: "team", Value: "core"}},
	})
	requireNoErr(t, err, "create role")
	check(t, r.ARN == "arn:aws:iam::123456789012:role/svc/App" && strings.HasPrefix(r.ID, "AROA"),
		"role = %+v", r)
	_, err = s.CreateRole(ctx, contracts.CreateRoleInput{
		AccountID: member, Name: "app", Path: "/", TrustPolicy: "{}",
	})
	requireErr(t, err, contracts.ErrRoleExists)

	desc := ""
	requireNoErr(t, s.UpdateRole(ctx, contracts.UpdateRoleInput{
		AccountID: member, Name: "app", Description: &desc, MaxSessionDuration: 7200,
	}), "update role")
	requireNoErr(
		t,
		s.UpdateAssumeRolePolicy(
			ctx,
			member,
			"APP",
			contracts.OrganizationTrustPolicy(member),
			nil,
		),
		"update trust",
	)
	got, err := s.GetRole(ctx, member, "app")
	requireNoErr(t, err, "get role")
	check(t, got.Name == "App" && got.Description == "" && got.MaxSessionDuration == 7200 &&
		got.TrustPolicy == contracts.OrganizationTrustPolicy(member) && len(got.Tags) == 1,
		"role = %+v", got)

	page, err := s.ListRoles(ctx, contracts.ListRolesInput{
		AccountID: member, PathPrefix: "/svc/", MaxItems: 10,
	})
	requireNoErr(t, err, "list roles")
	check(t, len(page.Items) == 1 && page.Items[0].ID == r.ID, "roles = %+v", page)
}

func TestTheOrganizationRole(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)
	r := organizationRole(t, s)
	again := organizationRole(t, s)
	check(t, again.ID == r.ID && r.MaxSessionDuration == contracts.RoleMaxSessionDuration &&
		r.TrustPolicy == contracts.OrganizationTrustPolicy(
			management,
		), "role = %+v, again %+v", r, again)

	page, err := s.ListAttachedPolicies(ctx, contracts.ListAttachedPoliciesInput{
		Entity: role(contracts.OrganizationRoleName), PathPrefix: "/", MaxItems: 10,
	})
	requireNoErr(t, err, "list attached")
	check(t, len(page.Items) == 1 && page.Items[0].ARN == contracts.AdministratorAccessARN,
		"attached = %+v", page.Items)
}

func TestEffectivePolicies(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)
	createUser(t, s, member)
	createRole(t, s)
	p := createPolicy(t, s, member, "managed")
	_, err := s.CreatePolicyVersion(ctx, member, p.ARN, doc("iam:ListUsers"), true)
	requireNoErr(t, err, "create version")

	for _, e := range []contracts.Entity{user(member), role("app")} {
		requireNoErr(t, s.PutInlinePolicy(ctx, e, "inline", doc("iam:GetRole")), "put inline")
		requireNoErr(t, s.AttachPolicy(ctx, e, p.ARN), "attach")
	}
	k, err := s.CreateAccessKey(ctx, member, "dev")
	requireNoErr(t, err, "create key")
	r, err := s.GetRole(ctx, member, "app")
	requireNoErr(t, err, "get role")
	rs, err := s.CreateRoleSession(ctx, contracts.CreateRoleSessionInput{
		Role: r, SessionName: "s1", Duration: 3600e9,
	})
	requireNoErr(t, err, "create session")

	// A user's and a session's role's: inline first, then the managed
	// policy's default version.
	want := []string{doc("iam:GetRole"), doc("iam:ListUsers")}
	for name, scope := range map[string]struct{ key, token string }{
		"user":    {k.ID, ""},
		"session": {rs.AccessKeyID, rs.SessionToken},
	} {
		key, kErr := s.SigningKey(ctx, scopeOf(scope.key, scope.token))
		requireNoErr(t, kErr, name+" signing key")
		got := make([]string, 0, len(key.Principal.Policies))
		for _, d := range key.Principal.Policies {
			got = append(got, string(d))
		}
		check(t, !key.Principal.Root && strings.Join(got, "|") == strings.Join(want, "|"),
			"%s policies = %v", name, got)
	}
	pr, err := s.Principal(ctx, rs.AccessKeyID)
	requireNoErr(t, err, "session principal")
	check(t, pr.RoleARN == r.ARN, "role ARN = %s", pr.RoleARN)

	// The root user is Root, with none.
	key, err := s.SigningKey(ctx, scopeOf(rootKeyID, ""))
	requireNoErr(t, err, "root signing key")
	check(t, key.Principal.Root && key.Principal.Policies == nil, "root = %+v", key.Principal)

	// A session whose role is gone has none.
	for _, e := range []func() error{
		func() error { return s.DetachPolicy(ctx, role("app"), p.ARN) },
		func() error { return s.DeleteInlinePolicy(ctx, role("app"), "inline") },
		func() error { return s.DeleteRole(ctx, member, "app") },
	} {
		requireNoErr(t, e(), "remove the role")
	}
	key, err = s.SigningKey(ctx, scopeOf(rs.AccessKeyID, rs.SessionToken))
	requireNoErr(t, err, "orphaned session key")
	check(t, key.Principal.Policies == nil, "orphaned session = %+v", key.Principal)
}

func TestASessionIsBoundToItsRolesID(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)
	r := createRole(t, s)
	rs, err := s.CreateRoleSession(ctx, contracts.CreateRoleSessionInput{
		Role: r, SessionName: "s1", Duration: 3600e9,
	})
	requireNoErr(t, err, "create session")
	pr, err := s.Principal(ctx, rs.AccessKeyID)
	requireNoErr(t, err, "session principal")
	check(t, !pr.Orphaned && pr.RoleARN == r.ARN, "principal = %+v", pr)

	// A role created again with the name is another role: the session is
	// orphaned, with no role ARN, and gets none of the new role's policies.
	requireNoErr(t, s.DeleteRole(ctx, member, "app"), "delete role")
	again := createRole(t, s)
	requireNoErr(t, s.PutInlinePolicy(ctx, role("app"), "inline", doc("iam:GetRole")), "put")
	pr, err = s.Principal(ctx, rs.AccessKeyID)
	requireNoErr(t, err, "orphaned session principal")
	check(t, pr.Orphaned && pr.RoleARN == "" && pr.PrincipalARN() == "" && again.ID != r.ID,
		"orphaned principal = %+v", pr)
	key, err := s.SigningKey(ctx, scopeOf(rs.AccessKeyID, rs.SessionToken))
	requireNoErr(t, err, "orphaned session key")
	check(t, key.Principal.Policies == nil, "orphaned session = %+v", key.Principal)
}

func TestTheOrganizationRoleIsCreatedOnce(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)
	created, err := s.OrganizationRoleCreated(ctx, member)
	requireNoErr(t, err, "created before")
	check(t, !created, "created before the first AssumeRole")
	organizationRole(t, s)
	created, err = s.OrganizationRoleCreated(ctx, member)
	requireNoErr(t, err, "created after")
	check(t, created, "not recorded as created")

	// Deleted by the account, it stays deleted.
	requireNoErr(t, s.DetachPolicy(ctx, role(contracts.OrganizationRoleName),
		contracts.AdministratorAccessARN), "detach")
	requireNoErr(t, s.DeleteRole(ctx, member, contracts.OrganizationRoleName), "delete")
	_, err = s.CreateOrganizationRole(ctx, member, management)
	requireErr(t, err, contracts.ErrOrganizationRoleCreated)
	_, err = s.GetRole(ctx, member, contracts.OrganizationRoleName)
	requireErr(t, err, contracts.ErrRoleNotFound)
}
