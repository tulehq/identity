package sqlimpl

import (
	"context"
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
