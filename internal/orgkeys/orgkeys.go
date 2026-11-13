// Package orgkeys tells the values of aws:PrincipalOrgID and
// aws:PrincipalOrgPaths for the principals of an account, from the accounts
// service, cached for a short time.
//
// AWS includes both keys in the request context "only if the principal is a
// member of an organization", and aws:PrincipalOrgID "also applies to the
// management account" (the IAM User Guide, AWS global condition context
// keys). So a principal of an ACTIVE member account, or of the management
// account, has them, and any other principal has neither. When the accounts
// service cannot be asked, the keys are unknown, never absent: an absent key
// satisfies a negated operator, so a condition such as StringNotEquals on
// aws:PrincipalOrgID would grant, or let a Deny lapse, for a principal whose
// organization is not known.
package orgkeys

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sync"
	"time"

	"golang.org/x/sync/singleflight"

	"tule.dev/identity/internal/contracts"
)

// TTL is how long an account's keys are kept once the accounts service has
// told them, counted from when the lookup began, so no keys are served more
// than TTL after the accounts service was asked for them. Within it, a
// change to the organization (an account moved, removed, closed, or the
// organization deleted) is not seen: a principal keeps the keys it had for
// at most TTL.
const TTL = 30 * time.Second

// UnknownTTL is how long a failed lookup is kept: for that long the
// account's keys are unknown without asking the accounts service again.
// Every request of an account whose keys are not kept looks them up, and
// the signing-key endpoint is asked before a request's signature is
// checked, so without it anyone holding an access key ID, without its
// secret, could make identity wait on an unreachable accounts service for
// every request. A failed lookup is only ever kept as unknown.
const UnknownTTL = time.Second

// lookupTimeout bounds one lookup, so an accounts service that does not
// answer delays a request by at most this long before its keys are
// reported unknown.
const lookupTimeout = 5 * time.Second

// Keys are an account's principals' organization keys.
type Keys struct {
	// OrgID is the value of aws:PrincipalOrgID, empty when the account is
	// in no organization or the keys are Unknown.
	OrgID string
	// Paths are the values of aws:PrincipalOrgPaths: the account's one
	// path, nil whenever OrgID is empty.
	Paths []string
	// Unknown is set when the accounts service could not be asked.
	Unknown bool
}

// Source tells an account's principals' organization keys. For returns an
// error exactly when it could not tell them; a caller must then take the
// keys as unknown, whatever Keys it returns.
type Source interface {
	For(ctx context.Context, accountID string) (Keys, error)
}

// entry is an account's lookup: its keys, or for a failed one its error,
// and when the lookup began.
type entry struct {
	at   time.Time
	err  error
	keys Keys
}

// fresh reports whether e may still be served at now.
func (e *entry) fresh(now time.Time) bool {
	ttl := TTL
	if e.err != nil {
		ttl = UnknownTTL
	}
	return now.Sub(e.at) < ttl
}

// Cache looks the keys up in an AccountDirectory and keeps them for TTL, or
// a failed lookup for UnknownTTL. Concurrent lookups of one account are one
// call to the accounts service. It keeps one entry per account it is asked
// about, and is only asked about the accounts of principals identity holds,
// so its size is bounded by theirs. It is safe for concurrent use.
type Cache struct {
	dir     contracts.AccountDirectory
	now     func() time.Time
	entries map[string]entry
	group   singleflight.Group
	mu      sync.Mutex
}

var _ Source = (*Cache)(nil)

// New returns a Cache over dir, telling the time by now.
func New(dir contracts.AccountDirectory, now func() time.Time) *Cache {
	return &Cache{dir: dir, now: now, entries: map[string]entry{}}
}

// For returns the keys of accountID's principals. When the accounts service
// cannot be asked, it returns Keys with Unknown set and the error, for the
// caller to log; the caller must then supply the keys as unknown. With no
// accounts service configured there is no organization, and the keys are
// absent, not unknown.
func (c *Cache) For(ctx context.Context, accountID string) (Keys, error) {
	if e, ok := c.kept(accountID); ok {
		return e.result()
	}
	// The lookup is shared by every request that waits on it, so it is not
	// cut short when the request that began it is.
	v, _, _ := c.group.Do(accountID, func() (any, error) {
		if e, ok := c.kept(accountID); ok {
			return e, nil
		}
		return c.lookup(context.WithoutCancel(ctx), accountID), nil
	})
	e, _ := v.(entry)
	return e.result()
}

// kept returns the account's entry while it may be served.
func (c *Cache) kept(accountID string) (entry, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.entries[accountID]
	return e, ok && e.fresh(c.now())
}

// lookup asks the accounts service for the account's keys, and keeps the
// answer unless a lookup that began later is kept already.
func (c *Cache) lookup(ctx context.Context, accountID string) entry {
	e := entry{at: c.now()}
	ctx, cancel := context.WithTimeout(ctx, lookupTimeout)
	defer cancel()
	org, err := c.dir.OrganizationOf(ctx, accountID)
	switch {
	case errors.Is(err, contracts.ErrNoAccountDirectory):
	case err != nil:
		e.err = fmt.Errorf("orgkeys: the organization of %s: %w", accountID, err)
	case org.ID != "":
		e.keys = Keys{OrgID: org.ID, Paths: []string{org.Path}}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if old, ok := c.entries[accountID]; !ok || !old.at.After(e.at) {
		c.entries[accountID] = e
	}
	return e
}

// result is what For answers from e: unknown keys and the error for a
// failed lookup, and otherwise a copy of the keys, so a caller cannot
// change a kept entry.
func (e *entry) result() (Keys, error) {
	if e.err != nil {
		return Keys{Unknown: true}, e.err
	}
	k := e.keys
	k.Paths = slices.Clone(k.Paths)
	return k, nil
}
