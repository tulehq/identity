package orgkeys

import (
	"context"
	"errors"
	"reflect"
	"sync"
	"testing"
	"time"

	"tule.dev/identity/internal/contracts"
)

const (
	management = "000000000000"
	member     = "111111111111"
	outsider   = "222222222222"
	orgID      = "o-a1b2c3d4e5"
)

// directory is an AccountDirectory over a fixed organization, counting the
// lookups it answers, and failing them all while down.
type directory struct {
	orgs  map[string]contracts.Organization
	err   error
	calls int
	mu    sync.Mutex
}

func (d *directory) ManagementAccountID(context.Context) (string, error) {
	return management, nil
}

func (d *directory) IsActiveMember(_ context.Context, account string) (bool, error) {
	_, ok := d.orgs[account]
	return ok, nil
}

func (d *directory) OrganizationOf(
	_ context.Context,
	account string,
) (contracts.Organization, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.calls++
	if d.err != nil {
		return contracts.Organization{}, d.err
	}
	return d.orgs[account], nil
}

func newDirectory() *directory {
	return &directory{orgs: map[string]contracts.Organization{
		management: {ID: orgID, Path: orgID + "/r-ab12/"},
		member:     {ID: orgID, Path: orgID + "/r-ab12/ou-ab12-11111111/"},
	}}
}

type clock struct{ t time.Time }

func (c *clock) now() time.Time { return c.t }

func TestKeysOfMembersTheManagementAccountAndOutsiders(t *testing.T) {
	c := New(newDirectory(), time.Now)
	for account, want := range map[string]Keys{
		management: {OrgID: orgID, Paths: []string{orgID + "/r-ab12/"}},
		member:     {OrgID: orgID, Paths: []string{orgID + "/r-ab12/ou-ab12-11111111/"}},
		outsider:   {},
	} {
		got, err := c.For(t.Context(), account)
		if err != nil || !reflect.DeepEqual(got, want) {
			t.Errorf("keys of %s = %+v, %v; want %+v", account, got, err, want)
		}
	}
}

func TestKeysAreKeptForTheTTL(t *testing.T) {
	d, clk := newDirectory(), &clock{t: time.Unix(1_800_000_000, 0)}
	c := New(d, clk.now)
	first, _ := c.For(t.Context(), member)

	// Removed from the organization, the account keeps its keys until the
	// entry is TTL old.
	delete(d.orgs, member)
	clk.t = clk.t.Add(TTL - time.Second)
	if got, _ := c.For(t.Context(), member); !reflect.DeepEqual(got, first) {
		t.Fatalf("keys within the TTL = %+v; want %+v", got, first)
	}
	clk.t = clk.t.Add(time.Second)
	if got, _ := c.For(t.Context(), member); !reflect.DeepEqual(got, Keys{}) {
		t.Fatalf("keys after the TTL = %+v; want none", got)
	}
	if d.calls != 2 {
		t.Fatalf("%d lookups; want 2", d.calls)
	}
}

func TestAFailedLookupIsUnknownAndNotKept(t *testing.T) {
	d := newDirectory()
	d.err = errors.New("connection refused")
	c := New(d, time.Now)
	got, err := c.For(t.Context(), member)
	if err == nil || !reflect.DeepEqual(got, Keys{Unknown: true}) {
		t.Fatalf("keys = %+v, %v; want unknown and the error", got, err)
	}

	// Once the accounts service answers, the next request has the keys.
	d.err = nil
	got, err = c.For(t.Context(), member)
	if err != nil || got.OrgID != orgID {
		t.Fatalf("keys after recovery = %+v, %v; want the member's", got, err)
	}
}

func TestNoAccountsServiceMeansNoOrganization(t *testing.T) {
	d := newDirectory()
	d.err = contracts.ErrNoAccountDirectory
	got, err := New(d, time.Now).For(t.Context(), member)
	if err != nil || !reflect.DeepEqual(got, Keys{}) {
		t.Fatalf("keys = %+v, %v; want none, known", got, err)
	}
}

func TestACallerCannotChangeACachedEntry(t *testing.T) {
	c := New(newDirectory(), time.Now)
	got, _ := c.For(t.Context(), member)
	got.Paths[0] = "changed"
	if again, _ := c.For(t.Context(), member); again.Paths[0] == "changed" {
		t.Fatal("changing the returned paths changed the cache")
	}
}
