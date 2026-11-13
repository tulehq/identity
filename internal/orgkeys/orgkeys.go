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

	"tule.dev/identity/internal/contracts"
)

// TTL is how long an account's keys are kept once the accounts service has
// told them. Within it, a change to the organization (an account moved,
// removed, closed, or the organization deleted) is not seen: a principal
// keeps the keys it had for at most TTL. A lookup that fails is not kept,
// so the next request asks again.
const TTL = 30 * time.Second

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

type entry struct {
	at   time.Time
	keys Keys
}

// Cache looks the keys up in an AccountDirectory and keeps them for TTL. It
// keeps one entry per account it is asked about, and is only asked about
// the accounts of principals identity holds, so its size is bounded by
// theirs. It is safe for concurrent use.
type Cache struct {
	dir     contracts.AccountDirectory
	now     func() time.Time
	entries map[string]entry
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
	c.mu.Lock()
	e, ok := c.entries[accountID]
	c.mu.Unlock()
	if ok && c.now().Sub(e.at) < TTL {
		return e.keys.clone(), nil
	}

	ctx, cancel := context.WithTimeout(ctx, lookupTimeout)
	defer cancel()
	org, err := c.dir.OrganizationOf(ctx, accountID)
	switch {
	case errors.Is(err, contracts.ErrNoAccountDirectory):
		org = contracts.Organization{}
	case err != nil:
		return Keys{Unknown: true}, fmt.Errorf("orgkeys: the organization of %s: %w",
			accountID, err)
	}
	var keys Keys
	if org.ID != "" {
		keys = Keys{OrgID: org.ID, Paths: []string{org.Path}}
	}
	c.mu.Lock()
	c.entries[accountID] = entry{at: c.now(), keys: keys}
	c.mu.Unlock()
	return keys.clone(), nil
}

// clone returns k with its own Paths, so a caller cannot change a cached
// entry.
func (k Keys) clone() Keys {
	k.Paths = slices.Clone(k.Paths)
	return k
}
