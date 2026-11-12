//go:build e2e

package e2e

import (
	"fmt"
	"maps"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/iam/types"
)

// maxTags is the quota of tags per IAM user (IAM and STS quotas), and the
// most a tag list may hold (tagListType).
const maxTags = 50

func tag(k, v string) types.Tag {
	return types.Tag{Key: aws.String(k), Value: aws.String(v)}
}

// tagMap turns tags into a map, failing on a key listed twice.
func tagMap(t *testing.T, tags []types.Tag) map[string]string {
	t.Helper()
	m := make(map[string]string, len(tags))
	for _, tg := range tags {
		k := aws.ToString(tg.Key)
		if _, dup := m[k]; dup {
			t.Fatalf("tag %q listed twice in %v", k, tags)
		}
		m[k] = aws.ToString(tg.Value)
	}
	return m
}

func requireTags(t *testing.T, got []types.Tag, want map[string]string, what string) {
	t.Helper()
	if m := tagMap(t, got); !maps.Equal(m, want) {
		t.Fatalf("%s: got %v, want %v", what, m, want)
	}
}

// userTags lists a user's tags through the ListUserTags paginator.
func userTags(t *testing.T, c *iam.Client, user string) []types.Tag {
	t.Helper()
	var tags []types.Tag
	p := iam.NewListUserTagsPaginator(c, &iam.ListUserTagsInput{UserName: aws.String(user)})
	for p.HasMorePages() {
		page, err := p.NextPage(t.Context())
		requireNoErr(t, err, "list user tags of "+user)
		tags = append(tags, page.Tags...)
	}
	return tags
}

func tagUser(t *testing.T, c *iam.Client, user string, tags ...types.Tag) {
	t.Helper()
	_, err := c.TagUser(t.Context(), &iam.TagUserInput{UserName: aws.String(user), Tags: tags})
	requireNoErr(t, err, "tag user "+user)
}

func TestCreateUserWithTags(t *testing.T) {
	_, c := rootIAM(t)
	want := map[string]string{"team": "platform", "cost-center": "41200", "empty": ""}

	out, err := c.CreateUser(t.Context(), &iam.CreateUserInput{
		UserName: aws.String("tagged"),
		Tags: []types.Tag{
			tag("team", "platform"),
			tag("cost-center", "41200"),
			tag("empty", ""),
		},
	})
	requireNoErr(t, err, "create user with tags")
	requireTags(t, out.User.Tags, want, "CreateUser tags")

	got, err := c.GetUser(t.Context(), &iam.GetUserInput{UserName: aws.String("tagged")})
	requireNoErr(t, err, "get user")
	requireTags(t, got.User.Tags, want, "GetUser tags")

	requireTags(t, userTags(t, c, "tagged"), want, "ListUserTags")

	// ListUsers "does not return the following attributes ...: Tags".
	t.Run("ListUsers leaves tags out", func(t *testing.T) {
		list, err := c.ListUsers(t.Context(), &iam.ListUsersInput{})
		requireNoErr(t, err, "list users")
		requireEqual(t, len(list.Users), 1, "user count")
		requireEqual(t, len(list.Users[0].Tags), 0, "tags in ListUsers")
	})
}

func TestTagAndUntagUser(t *testing.T) {
	_, c := rootIAM(t)
	createUser(t, c, "dev")

	// ListUserTags: an untagged user has an empty list.
	requireTags(t, userTags(t, c, "dev"), map[string]string{}, "tags of a new user")

	tagUser(t, c, "dev", tag("Department", "finance"), tag("project", "alpha"))
	requireTags(t, userTags(t, c, "dev"),
		map[string]string{"Department": "finance", "project": "alpha"}, "after TagUser")

	// TagUser: "If a tag with the same key name already exists, then that
	// tag is overwritten with the new value."
	t.Run("same key overwrites", func(t *testing.T) {
		tagUser(t, c, "dev", tag("project", "beta"))
		requireEqual(t, tagMap(t, userTags(t, c, "dev"))["project"], "beta", "project")
	})

	// Tagging rules: user tag keys are not case sensitive; "If you have
	// tagged a user with the Department=finance tag and you add the
	// department=hr tag, it replaces the first tag. A second tag is not
	// added." Which spelling is kept is not stated, so only the count and
	// the value are checked.
	t.Run("other case replaces", func(t *testing.T) {
		tagUser(t, c, "dev", tag("department", "hr"))
		m := tagMap(t, userTags(t, c, "dev"))
		requireEqual(t, len(m), 2, "tag count")
		var value string
		for k, v := range m {
			if strings.EqualFold(k, "department") {
				value = v
			}
		}
		requireEqual(t, value, "hr", "department value")
	})

	t.Run("UntagUser", func(t *testing.T) {
		_, err := c.UntagUser(t.Context(), &iam.UntagUserInput{
			UserName: aws.String("dev"), TagKeys: []string{"project"},
		})
		requireNoErr(t, err, "untag user")
		m := tagMap(t, userTags(t, c, "dev"))
		if _, ok := m["project"]; ok || len(m) != 1 {
			t.Fatalf("tags after untagging project: %v", m)
		}
	})

	// Assumption: keys not being case sensitive holds for UntagUser too.
	t.Run("UntagUser in another case", func(t *testing.T) {
		_, err := c.UntagUser(t.Context(), &iam.UntagUserInput{
			UserName: aws.String("dev"), TagKeys: []string{"DEPARTMENT"},
		})
		requireNoErr(t, err, "untag user")
		requireTags(t, userTags(t, c, "dev"), map[string]string{}, "tags after untagging all")
	})
}

func TestListUserTagsPaginator(t *testing.T) {
	_, c := rootIAM(t)
	createUser(t, c, "dev")
	want := map[string]string{}
	tags := make([]types.Tag, 0, 5)
	for i := range 5 {
		k, v := fmt.Sprintf("key%d", i), fmt.Sprintf("value%d", i)
		want[k] = v
		tags = append(tags, tag(k, v))
	}
	tagUser(t, c, "dev", tags...)

	p := iam.NewListUserTagsPaginator(c, &iam.ListUserTagsInput{UserName: aws.String("dev")},
		func(o *iam.ListUserTagsPaginatorOptions) { o.Limit = 2 })
	var got []types.Tag
	got2 := walkPages(t, 2, p.HasMorePages, p.NextPage, func(o *iam.ListUserTagsOutput) []string {
		got = append(got, o.Tags...)
		keys := make([]string, 0, len(o.Tags))
		for _, tg := range o.Tags {
			keys = append(keys, aws.ToString(tg.Key))
		}
		return keys
	})
	requireEqual(t, len(got2), 5, "tags listed")
	requireTags(t, got, want, "paged tags")
}

func TestTagLimits(t *testing.T) {
	_, c := rootIAM(t)
	createUser(t, c, "dev")
	full := make([]types.Tag, 0, maxTags+1)
	for i := range maxTags + 1 {
		full = append(full, tag(fmt.Sprintf("k%02d", i), "v"))
	}

	// tagKeyType: 1 to 128 characters of [\p{L}\p{Z}\p{N}_.:/=+\-@];
	// tagValueType: 0 to 256 of the same; tagListType: at most 50. The Go
	// SDK checks none of them, and AWS answers constraint failures with
	// ValidationError (Common Error Types).
	invalid := map[string][]types.Tag{
		"51 tags in one request": full,
		"empty key":              {tag("", "v")},
		"key of 129":             {tag(strings.Repeat("k", 129), "v")},
		"key with a star":        {tag("a*b", "v")},
		"value of 257":           {tag("k", strings.Repeat("v", 257))},
		"value with a star":      {tag("k", "a*b")},
	}
	for name, tags := range invalid {
		t.Run("TagUser "+name, func(t *testing.T) {
			err := errOf(c.TagUser(t.Context(), &iam.TagUserInput{
				UserName: aws.String("dev"), Tags: tags,
			}))
			requireCode(t, err, codeValidation)
		})
	}

	t.Run("longest key and value", func(t *testing.T) {
		tagUser(t, c, "dev", tag(strings.Repeat("k", 128), strings.Repeat("v", 256)),
			tag("a b_c.d:e/f=g+h-i@j", "x"))
	})
	_, err := c.UntagUser(t.Context(), &iam.UntagUserInput{
		UserName: aws.String("dev"),
		TagKeys:  []string{strings.Repeat("k", 128), "a b_c.d:e/f=g+h-i@j"},
	})
	requireNoErr(t, err, "untag the longest key")

	// The quota: 50 tags per user. Going past it with a request the model
	// accepts is LimitExceeded, in TagUser's errors ("beyond the current
	// Amazon Web Services account limits").
	t.Run("51st tag", func(t *testing.T) {
		tagUser(t, c, "dev", full[:maxTags]...)
		err := errOf(c.TagUser(t.Context(), &iam.TagUserInput{
			UserName: aws.String("dev"), Tags: full[maxTags:],
		}))
		requireAs[*types.LimitExceededException](t, err)
		requireEqual(t, len(userTags(t, c, "dev")), maxTags, "tag count")

		// Overwriting a tag of a full user adds none, so it is allowed.
		tagUser(t, c, "dev", tag("k00", "new"))
	})
}

func TestTagRules(t *testing.T) {
	// Tagging rules (IAM User Guide, "Rules for tagging in IAM and AWS
	// STS"): no key or value may begin with aws:, and an entity cannot
	// hold the same key twice, keys of users compared without case.
	// Assumption: the reference names no error for these; both are
	// InvalidInput, which TagUser and CreateUser list, and which IAM sends
	// for them ("User tags beginning with 'aws:' are reserved for system
	// use", "Duplicate tag keys found").
	_, c := rootIAM(t)
	createUser(t, c, "dev")

	tests := map[string][]types.Tag{
		"aws: key":             {tag("aws:team", "v")},
		"aws: key, upper case": {tag("AWS:team", "v")},
		"aws: value":           {tag("team", "aws:v")},
		"duplicate keys":       {tag("team", "a"), tag("team", "b")},
		"keys differing in case": {
			tag("team", "a"), tag("Team", "b"),
		},
	}
	for name, tags := range tests {
		t.Run("TagUser "+name, func(t *testing.T) {
			err := errOf(c.TagUser(t.Context(), &iam.TagUserInput{
				UserName: aws.String("dev"), Tags: tags,
			}))
			requireAs[*types.InvalidInputException](t, err)
		})
		t.Run("CreateUser "+name, func(t *testing.T) {
			user := "u" + strings.NewReplacer(" ", "", ":", "", ",", "").Replace(name)
			err := errOf(c.CreateUser(t.Context(), &iam.CreateUserInput{
				UserName: aws.String(user), Tags: tags,
			}))
			requireAs[*types.InvalidInputException](t, err)
			// CreateUserInput.Tags: "the entire request fails and the
			// resource is not created".
			requireAs[*types.NoSuchEntityException](t, errOf(c.GetUser(t.Context(),
				&iam.GetUserInput{UserName: aws.String(user)})))
		})
	}

	requireTags(t, userTags(t, c, "dev"), map[string]string{}, "tags after refused requests")
}

func TestTagsOfUnknownUser(t *testing.T) {
	// NoSuchEntity is in the errors of all three operations.
	_, c := rootIAM(t)
	name := aws.String("nobody")

	t.Run("TagUser", func(t *testing.T) {
		requireAs[*types.NoSuchEntityException](t, errOf(c.TagUser(t.Context(),
			&iam.TagUserInput{UserName: name, Tags: []types.Tag{tag("k", "v")}})))
	})
	t.Run("UntagUser", func(t *testing.T) {
		requireAs[*types.NoSuchEntityException](t, errOf(c.UntagUser(t.Context(),
			&iam.UntagUserInput{UserName: name, TagKeys: []string{"k"}})))
	})
	t.Run("ListUserTags", func(t *testing.T) {
		requireAs[*types.NoSuchEntityException](t, errOf(c.ListUserTags(t.Context(),
			&iam.ListUserTagsInput{UserName: name})))
	})
}

func TestUserKeyCannotTag(t *testing.T) {
	// The spec's admin rule covers every IAM operation.
	srv, c := rootIAM(t)
	key := userWithKey(t, c, "plain")
	tagUser(t, c, "plain", tag("seed", "1"))
	err := errOf(iamFor(srv, key).TagUser(t.Context(), &iam.TagUserInput{
		UserName: aws.String("plain"), Tags: []types.Tag{tag("k", "v")},
	}))
	requireCode(t, err, codeAccessDenied)
	requireTags(t, userTags(t, c, "plain"), map[string]string{"seed": "1"}, "tags")
}
