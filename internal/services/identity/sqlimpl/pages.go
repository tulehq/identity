package sqlimpl

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"strconv"
	"strings"

	"tule.dev/identity/internal/contracts"
)

// A marker binds the listing it was issued for, by a hash of the account,
// the listing and its scope (the path prefix or user it was asked for), and
// carries the cursor of the last item it returned. It is only accepted back
// by the same listing with the same scope in the same account, so one from
// another listing, or one this service did not issue, fails rather than
// resuming somewhere arbitrary.
//
// Only the hash is carried for the scope, so a marker stays short whatever
// the scope: markerType allows 320 characters, and the longest cursor is a
// managed policy's name and ID, 128 and 21 ASCII characters and a
// separator, which with the hash encodes to 216.
const markerHashSize = 12

// The listings a marker can belong to.
const (
	listUsers = "users"
	listKeys  = "access-keys"
	listTags  = "user-tags"

	listPolicies       = "policies"
	listPolicyVersions = "policy-versions"
	listAttached       = "attached-policies"
	listInline         = "inline-policies"
	listRoles          = "roles"
)

// cursorSeparator joins the parts of a cursor made of two: a name and an ID,
// neither of which can contain it.
const cursorSeparator = "\x00"

func joinCursor(name, id string) string {
	return name + cursorSeparator + id
}

// splitCursor splits a cursor joinCursor made; an empty one splits into
// empty parts.
func splitCursor(cursor string) (name, id string) {
	name, id, _ = strings.Cut(cursor, cursorSeparator)
	return name, id
}

func markerHash(accountID, list, scope string) []byte {
	h := sha256.New()
	for _, part := range []string{accountID, list, scope} {
		h.Write([]byte(strconv.Itoa(len(part)) + ":" + part))
	}
	return h.Sum(nil)[:markerHashSize]
}

func encodeMarker(accountID, list, scope, cursor string) string {
	raw := append(markerHash(accountID, list, scope), cursor...)
	return base64.RawURLEncoding.EncodeToString(raw)
}

// decodeMarker returns the cursor a listing should resume after, or "" for
// an empty marker.
func decodeMarker(marker, accountID, list, scope string) (string, error) {
	if marker == "" {
		return "", nil
	}
	raw, err := base64.RawURLEncoding.DecodeString(marker)
	if err != nil || len(raw) <= markerHashSize ||
		!bytes.Equal(raw[:markerHashSize], markerHash(accountID, list, scope)) {
		return "", contracts.ErrInvalidMarker
	}
	return string(raw[markerHashSize:]), nil
}

// decodeIntMarker is decodeMarker for the listings whose cursor is a
// non-negative integer: a rowid or an offset. It returns 0 for an empty
// marker.
func decodeIntMarker(marker, accountID, list, scope string) (int64, error) {
	cursor, err := decodeMarker(marker, accountID, list, scope)
	if err != nil || cursor == "" {
		return 0, err
	}
	n, err := strconv.ParseInt(cursor, 10, 64)
	if err != nil || n < 0 {
		return 0, contracts.ErrInvalidMarker
	}
	return n, nil
}

// cursored is one item of a listing with the cursor that resumes after it.
type cursored[T any] struct {
	item   T
	cursor string
}

// paginate makes a page of up to size items from rows, which the query
// fetched with one more than size: when that extra row is there, the page has
// a marker for the next.
func paginate[T any](
	rows []cursored[T],
	size int,
	accountID, list, scope string,
) *contracts.Page[T] {
	page := &contracts.Page[T]{Items: make([]T, 0, min(len(rows), size))}
	for i, r := range rows {
		if i == size {
			page.Marker = encodeMarker(accountID, list, scope, rows[size-1].cursor)
			break
		}
		page.Items = append(page.Items, r.item)
	}
	return page
}
