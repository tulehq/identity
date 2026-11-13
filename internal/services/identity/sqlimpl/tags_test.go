package sqlimpl

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"testing"
	"time"

	"tule.dev/identity/internal/contracts"
	"tule.dev/identity/internal/queryapi"
)

func TestAMarkerFitsMarkerTypeWhateverTheScope(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)

	// The longest path and names the model allows: a 512-character path, and
	// user names of 64 characters.
	path := "/" + strings.Repeat("p", 510) + "/"
	for _, c := range []string{"a", "b", "c"} {
		_, err := s.CreateUser(ctx, management, strings.Repeat(c, 64), path, nil)
		requireNoErr(t, err, "create user")
	}

	in := contracts.ListUsersInput{AccountID: management, PathPrefix: path, MaxItems: 1}
	var names []string
	for range 3 {
		page, err := s.ListUsers(ctx, in)
		requireNoErr(t, err, "list users")
		check(t, len(page.Items) == 1, "page = %+v", page.Items)
		names = append(names, page.Items[0].Name[:1])
		if page.Marker == "" {
			break
		}
		// The marker must pass the model's markerType when sent back.
		requireNoErr(t, queryapi.Marker.Check("Marker", page.Marker), "marker")
		in.Marker = page.Marker
	}
	check(t, fmt.Sprint(names) == "[a b c]", "names = %v", names)
}

func TestUserTags(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)
	_, err := s.CreateUser(ctx, management, "dev", "/", []contracts.Tag{
		{Key: "Team", Value: "core"}, {Key: "Env", Value: "dev"},
	})
	requireNoErr(t, err, "create user")

	requireNoErr(t, s.TagUser(ctx, management, "dev", []contracts.Tag{{Key: "ENV", Value: "prod"}}),
		"replace a tag")
	u, err := s.GetUser(ctx, management, "dev")
	requireNoErr(t, err, "get user")
	check(t, fmt.Sprint(u.Tags) == "[{ENV prod} {Team core}]", "tags = %v", u.Tags)

	// Pages resume at an offset, and the marker is the listing's own.
	var keys []string
	in := contracts.ListUserTagsInput{AccountID: management, UserName: "dev", MaxItems: 1}
	for {
		page, lErr := s.ListUserTags(ctx, in)
		requireNoErr(t, lErr, "list user tags")
		for _, tg := range page.Items {
			keys = append(keys, tg.Key)
		}
		if page.Marker == "" {
			break
		}
		_, lErr = s.ListUsers(ctx, contracts.ListUsersInput{
			AccountID: management, PathPrefix: "/", MaxItems: 1, Marker: page.Marker,
		})
		requireErr(t, lErr, contracts.ErrInvalidMarker)
		in.Marker = page.Marker
	}
	check(t, fmt.Sprint(keys) == "[ENV Team]", "keys = %v", keys)

	requireNoErr(t, s.UntagUser(ctx, management, "dev", []string{"team", "absent"}), "untag")
	u, err = s.GetUser(ctx, management, "dev")
	requireNoErr(t, err, "get user")
	check(t, len(u.Tags) == 1, "tags after untag = %v", u.Tags)

	// A user deleted and created again starts without tags.
	requireNoErr(t, s.DeleteUser(ctx, management, "dev"), "delete user")
	_, err = s.CreateUser(ctx, management, "dev", "/", nil)
	requireNoErr(t, err, "create user again")
	u, err = s.GetUser(ctx, management, "dev")
	requireNoErr(t, err, "get user")
	check(t, len(u.Tags) == 0, "recreated user's tags = %v", u.Tags)
	requireErr(t, s.TagUser(ctx, member, "dev", nil), contracts.ErrUserNotFound)
}

func TestTagUserStopsAtTheLimit(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)
	tags := make([]contracts.Tag, 0, contracts.MaxTagsPerUser)
	for i := range contracts.MaxTagsPerUser {
		tags = append(tags, contracts.Tag{Key: fmt.Sprintf("k%d", i)})
	}
	_, err := s.CreateUser(ctx, management, "dev", "/", tags)
	requireNoErr(t, err, "create user")

	err = s.TagUser(ctx, management, "dev", []contracts.Tag{{Key: "new"}, {Key: "k0", Value: "x"}})
	requireErr(t, err, contracts.ErrTagLimitExceeded)
	u, err := s.GetUser(ctx, management, "dev")
	requireNoErr(t, err, "get user")
	for _, tg := range u.Tags {
		check(t, tg.Value == "", "a refused TagUser changed %v", tg)
	}
}

func TestTheRootUserIsAsOldAsTheStore(t *testing.T) {
	s := newStore(t)
	created, err := s.RootCreateDate(context.Background())
	requireNoErr(t, err, "root create date")
	check(t, time.Since(created) < time.Minute, "created = %v", created)
}

// Tag keys are compared with Unicode simple folding, as strings.EqualFold
// does, not only in ASCII as SQLite's NOCASE does: Ä and ä are one key, and
// so are the Kelvin sign and k.
func TestUserTagKeysFoldBeyondASCII(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)
	_, err := s.CreateUser(ctx, management, "dev", "/", []contracts.Tag{
		{Key: "Ä", Value: "1"}, {Key: "K", Value: "kelvin"},
	})
	requireNoErr(t, err, "create user")

	requireNoErr(t, s.TagUser(ctx, management, "dev", []contracts.Tag{
		{Key: "ä", Value: "2"}, {Key: "k", Value: "letter"},
	}), "tag with the keys in another case")
	u, err := s.GetUser(ctx, management, "dev")
	requireNoErr(t, err, "get user")
	check(t, fmt.Sprint(u.Tags) == "[{k letter} {ä 2}]", "tags = %v", u.Tags)

	// Within one call, a later key replaces an earlier one of another case.
	requireNoErr(t, s.TagUser(ctx, management, "dev", []contracts.Tag{
		{Key: "Ö", Value: "1"}, {Key: "ö", Value: "2"},
	}), "tag twice in one call")
	u, err = s.GetUser(ctx, management, "dev")
	requireNoErr(t, err, "get user")
	check(t, fmt.Sprint(u.Tags) == "[{k letter} {ä 2} {ö 2}]", "tags = %v", u.Tags)

	requireNoErr(t, s.UntagUser(ctx, management, "dev", []string{"Ä", "K", "Ö"}),
		"untag with the keys in another case")
	u, err = s.GetUser(ctx, management, "dev")
	requireNoErr(t, err, "get user")
	check(t, len(u.Tags) == 0, "tags after untag = %v", u.Tags)
}

// A role's tags, set on CreateRole, are unique by the same folding.
func TestRoleTagKeysFoldBeyondASCII(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)
	r, err := s.CreateRole(ctx, contracts.CreateRoleInput{
		AccountID: management, Name: "r", Path: "/",
		TrustPolicy:        `{"Version":"2012-10-17","Statement":[]}`,
		MaxSessionDuration: contracts.RoleMaxSessionDuration,
		Tags:               []contracts.Tag{{Key: "Ä", Value: "1"}, {Key: "ä", Value: "2"}},
	})
	requireNoErr(t, err, "create role")
	got, err := s.GetRole(ctx, management, r.Name)
	requireNoErr(t, err, "get role")
	check(t, fmt.Sprint(got.Tags) == "[{ä 2}]", "role tags = %v", got.Tags)
}

// A user may hold keys that fold to one, Ä and ä, stored before keys were
// folded beyond ASCII. Setting or removing the key replaces or removes them
// all.
func TestTagKeysStoredTwiceBeforeFoldingAreReplaced(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)
	legacy := func() {
		t.Helper()
		_, err := s.CreateUser(ctx, management, "dev", "/", nil)
		requireNoErr(t, err, "create user")
		requireNoErr(t, s.inTx(ctx, func(tx *sql.Tx) error {
			u, err := loadUser(ctx, tx, management, "dev")
			if err != nil {
				return err
			}
			for _, k := range []string{"Ä", "ä"} {
				if err = exec(ctx, tx,
					`INSERT INTO user_tags (user_id, key, value) VALUES (?, ?, 'old')`,
					u.ID, k); err != nil {
					return err
				}
			}
			return nil
		}), "store the key twice")
	}

	legacy()
	requireNoErr(t, s.TagUser(ctx, management, "dev", []contracts.Tag{{Key: "ä", Value: "new"}}),
		"tag the key again")
	u, err := s.GetUser(ctx, management, "dev")
	requireNoErr(t, err, "get user")
	check(t, fmt.Sprint(u.Tags) == "[{ä new}]", "tags = %v", u.Tags)

	requireNoErr(t, s.DeleteUser(ctx, management, "dev"), "delete user")
	legacy()
	requireNoErr(t, s.UntagUser(ctx, management, "dev", []string{"Ä"}), "untag the key")
	u, err = s.GetUser(ctx, management, "dev")
	requireNoErr(t, err, "get user")
	check(t, len(u.Tags) == 0, "tags after untag = %v", u.Tags)
}
