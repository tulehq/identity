//go:build e2e

package e2e

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/iam/types"
)

// walkPages reads every page from an SDK paginator and returns the names on
// them. MaxItems is the most a page may hold; IAM "might return fewer
// results, even when there are more results available" (ListUsersInput),
// so only the upper bound is checked per page. With more items than
// pageSize, the walk must take more than one page.
func walkPages[O any](
	t *testing.T,
	pageSize int,
	more func() bool,
	next func(context.Context, ...func(*iam.Options)) (O, error),
	names func(O) []string,
) []string {
	t.Helper()

	var got []string
	pages := 0
	for more() {
		out, err := next(t.Context())
		requireNoErr(t, err, "next page")
		pages++
		page := names(out)
		if len(page) > pageSize {
			t.Fatalf("page %d holds %d items, MaxItems is %d", pages, len(page), pageSize)
		}
		got = append(got, page...)
		if pages > 50 {
			t.Fatal("paginator did not finish")
		}
	}
	if pages < 2 {
		t.Fatalf("%d items came in %d page(s) with MaxItems %d", len(got), pages, pageSize)
	}
	return got
}

func TestListUsersPaginator(t *testing.T) {
	_, c := rootIAM(t)
	want := make([]string, 0, 5)
	for i := range 5 {
		want = append(want, createUser(t, c, fmt.Sprintf("user%d", i)))
	}

	p := iam.NewListUsersPaginator(
		c,
		&iam.ListUsersInput{},
		func(o *iam.ListUsersPaginatorOptions) {
			o.Limit = 2
		},
	)
	got := walkPages(t, 2, p.HasMorePages, p.NextPage,
		func(o *iam.ListUsersOutput) []string { return userNames(o.Users) })
	// requireSameNames also catches a user listed twice.
	requireSameNames(t, got, want)
}

func TestListUsersMarker(t *testing.T) {
	// ListUsersOutput: IsTruncated is true while more remain, and Marker is
	// then present, to pass as the next call's Marker.
	_, c := rootIAM(t)
	for i := range 3 {
		createUser(t, c, fmt.Sprintf("user%d", i))
	}

	first, err := c.ListUsers(t.Context(), &iam.ListUsersInput{MaxItems: aws.Int32(2)})
	requireNoErr(t, err, "first page")
	requireEqual(t, first.IsTruncated, true, "IsTruncated of the first page")
	if aws.ToString(first.Marker) == "" {
		t.Fatal("truncated page has no Marker")
	}

	var names []string
	names = append(names, userNames(first.Users)...)
	marker := first.Marker
	for range 5 {
		page, err := c.ListUsers(t.Context(), &iam.ListUsersInput{
			MaxItems: aws.Int32(2), Marker: marker,
		})
		requireNoErr(t, err, "next page")
		names = append(names, userNames(page.Users)...)
		if !page.IsTruncated {
			break
		}
		marker = page.Marker
	}
	requireSameNames(t, names, []string{"user0", "user1", "user2"})
}

func TestListUsersLongPathPrefix(t *testing.T) {
	// A path of 250 characters (pathType allows 512) and names of 64, the
	// longest userNameType allows, paged one user at a time. Every Marker
	// the service hands out must be one it accepts back: markerType is 1 to
	// 320 characters of \u0020-\u00FF.
	_, c := rootIAM(t)
	path := "/" + strings.Repeat("p", 248) + "/"
	want := []string{strings.Repeat("a", 64), strings.Repeat("b", 64)}
	for _, name := range want {
		_, err := c.CreateUser(t.Context(), &iam.CreateUserInput{
			UserName: aws.String(name), Path: aws.String(path),
		})
		requireNoErr(t, err, "create user")
	}

	p := iam.NewListUsersPaginator(c, &iam.ListUsersInput{PathPrefix: aws.String(path)},
		func(o *iam.ListUsersPaginatorOptions) { o.Limit = 1 })
	got := walkPages(t, 1, p.HasMorePages, p.NextPage, func(o *iam.ListUsersOutput) []string {
		if m := aws.ToString(o.Marker); o.IsTruncated && (m == "" || len(m) > 320) {
			t.Fatalf("Marker of %d characters is outside markerType", len(m))
		}
		return userNames(o.Users)
	})
	requireSameNames(t, got, want)
}

func TestListAccessKeysPaginator(t *testing.T) {
	// ListAccessKeys: "you can still paginate the results using the MaxItems
	// and Marker parameters".
	_, c := rootIAM(t)
	a := userWithKey(t, c, "dev")
	b := createKey(t, c, "dev")

	p := iam.NewListAccessKeysPaginator(c, &iam.ListAccessKeysInput{UserName: aws.String("dev")},
		func(o *iam.ListAccessKeysPaginatorOptions) { o.Limit = 1 })
	got := walkPages(t, 1, p.HasMorePages, p.NextPage,
		func(o *iam.ListAccessKeysOutput) []string { return keyIDs(o.AccessKeyMetadata) })
	requireSameNames(t, got, []string{a.AccessKeyID, b.AccessKeyID})
}

func TestMaxItemsBounds(t *testing.T) {
	// maxItemsType: 1 to 1000 (botocore iam).
	_, c := rootIAM(t)
	createUser(t, c, "dev")

	for _, n := range []int32{0, 1001} {
		t.Run(fmt.Sprintf("ListUsers %d", n), func(t *testing.T) {
			err := errOf(c.ListUsers(t.Context(), &iam.ListUsersInput{MaxItems: aws.Int32(n)}))
			requireCode(t, err, codeValidation)
		})
		t.Run(fmt.Sprintf("ListAccessKeys %d", n), func(t *testing.T) {
			err := errOf(c.ListAccessKeys(t.Context(), &iam.ListAccessKeysInput{
				UserName: aws.String("dev"), MaxItems: aws.Int32(n),
			}))
			requireCode(t, err, codeValidation)
		})
	}

	t.Run("ListUsers 1000", func(t *testing.T) {
		_, err := c.ListUsers(t.Context(), &iam.ListUsersInput{MaxItems: aws.Int32(1000)})
		requireNoErr(t, err, "list users with the largest MaxItems")
	})
}

func keyIDs(keys []types.AccessKeyMetadata) []string {
	ids := make([]string, 0, len(keys))
	for _, k := range keys {
		ids = append(ids, aws.ToString(k.AccessKeyId))
	}
	return ids
}
