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
	orgs map[string]contracts.Organization
	err  error
	// during, when set, runs inside each lookup, before it answers.
	during func()
	calls  int
	mu     sync.Mutex
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
	d.calls++
	during := d.during
	d.mu.Unlock()
	if during != nil {
		during()
	}
	d.mu.Lock()
	defer d.mu.Unlock()
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

func TestAFailedLookupIsUnknownForUnknownTTL(t *testing.T) {
	d, clk := newDirectory(), &clock{t: time.Unix(1_800_000_000, 0)}
	d.err = errors.New("connection refused")
	c := New(d, clk.now)
	got, err := c.For(t.Context(), member)
	if err == nil || !reflect.DeepEqual(got, Keys{Unknown: true}) {
		t.Fatalf("keys = %+v, %v; want unknown and the error", got, err)
	}

	// Within UnknownTTL the accounts service is not asked again, and the
	// keys stay unknown, with the error, even once it would answer.
	d.err = nil
	clk.t = clk.t.Add(UnknownTTL - time.Millisecond)
	got, err = c.For(t.Context(), member)
	if err == nil || !reflect.DeepEqual(got, Keys{Unknown: true}) || d.calls != 1 {
		t.Fatalf("keys within UnknownTTL = %+v, %v after %d lookups; want unknown, kept",
			got, err, d.calls)
	}

	// After it, the next request asks, and has the keys.
	clk.t = clk.t.Add(time.Millisecond)
	got, err = c.For(t.Context(), member)
	if err != nil || got.OrgID != orgID || d.calls != 2 {
		t.Fatalf("keys after UnknownTTL = %+v, %v after %d lookups; want the member's",
			got, err, d.calls)
	}
}

func TestAFailedLookupIsNeverKeptAsKnown(t *testing.T) {
	// A known entry that expires and then fails to refresh is unknown, not
	// the old keys.
	d, clk := newDirectory(), &clock{t: time.Unix(1_800_000_000, 0)}
	c := New(d, clk.now)
	if got, _ := c.For(t.Context(), member); got.OrgID != orgID {
		t.Fatalf("keys = %+v; want the member's", got)
	}
	d.err = errors.New("connection refused")
	clk.t = clk.t.Add(TTL)
	if got, err := c.For(t.Context(), member); err == nil || !got.Unknown || got.OrgID != "" {
		t.Fatalf("keys = %+v, %v; want unknown", got, err)
	}
}

func TestConcurrentLookupsOfAnAccountAreOne(t *testing.T) {
	d := newDirectory()
	release := make(chan struct{})
	d.during = func() { <-release }
	c := New(d, time.Now)

	const callers = 20
	var started, done sync.WaitGroup
	results := make([]Keys, callers)
	for i := range callers {
		started.Add(1)
		done.Add(1)
		go func() {
			defer done.Done()
			started.Done()
			results[i], _ = c.For(context.Background(), member)
		}()
	}
	started.Wait()
	// Let the callers reach the shared lookup before it answers.
	time.Sleep(50 * time.Millisecond)
	close(release)
	done.Wait()
	if d.calls != 1 {
		t.Fatalf("%d lookups for %d concurrent callers; want 1", d.calls, callers)
	}
	for i, r := range results {
		if r.OrgID != orgID {
			t.Fatalf("caller %d got %+v; want the member's keys", i, r)
		}
	}
}

func TestConcurrentFailedLookupsAreOne(t *testing.T) {
	d := newDirectory()
	d.err = errors.New("connection refused")
	release := make(chan struct{})
	d.during = func() { <-release }
	c := New(d, time.Now)

	const callers = 20
	var done sync.WaitGroup
	unknown := make([]bool, callers)
	for i := range callers {
		done.Add(1)
		go func() {
			defer done.Done()
			k, err := c.For(context.Background(), member)
			unknown[i] = k.Unknown && err != nil
		}()
	}
	time.Sleep(50 * time.Millisecond)
	close(release)
	done.Wait()
	if d.calls != 1 {
		t.Fatalf("%d lookups for %d concurrent callers; want 1", d.calls, callers)
	}
	for i, u := range unknown {
		if !u {
			t.Fatalf("caller %d did not get unknown keys and the error", i)
		}
	}
}

func TestKeysAreKeptForTheTTLFromWhenTheLookupBegan(t *testing.T) {
	// A lookup that takes 10 seconds is kept for TTL from when it began, so
	// its keys are never served more than TTL after the accounts service
	// was asked.
	d, clk := newDirectory(), &clock{t: time.Unix(1_800_000_000, 0)}
	began := clk.t
	d.during = func() { clk.t = clk.t.Add(10 * time.Second) }
	c := New(d, clk.now)
	_, _ = c.For(t.Context(), member)
	d.during = nil
	clk.t = began.Add(TTL)
	_, _ = c.For(t.Context(), member)
	if d.calls != 2 {
		t.Fatalf("%d lookups; want the entry expired TTL after its lookup began", d.calls)
	}
}

func TestALateLookupDoesNotReplaceANewerOne(t *testing.T) {
	d, clk := newDirectory(), &clock{t: time.Unix(1_800_000_000, 0)}
	c := New(d, clk.now)
	newer := entry{at: clk.t, keys: Keys{OrgID: "o-newernewer"}}
	c.entries[member] = newer

	// A lookup that began before the kept one finishes after it.
	clk.t = clk.t.Add(-time.Second)
	c.lookup(t.Context(), member)
	if got := c.entries[member]; !got.at.Equal(newer.at) || got.keys.OrgID != newer.keys.OrgID {
		t.Fatalf("entry = %+v; want the newer one kept", got)
	}

	// One that began after it replaces it.
	clk.t = newer.at.Add(time.Second)
	c.lookup(t.Context(), member)
	if got := c.entries[member]; got.keys.OrgID != orgID {
		t.Fatalf("entry = %+v; want the later lookup's", got)
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
