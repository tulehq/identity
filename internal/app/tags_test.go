package app

import (
	"fmt"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
)

func tag(k, v string) iamtypes.Tag {
	return iamtypes.Tag{Key: aws.String(k), Value: aws.String(v)}
}

// userTags lists the tags of the IAM user dev through the paginator, a page of
// one at a time, as "key=value".
func userTags(t *testing.T, c *iam.Client) []string {
	t.Helper()
	var out []string
	p := iam.NewListUserTagsPaginator(c, &iam.ListUserTagsInput{
		UserName: aws.String("dev"), MaxItems: aws.Int32(1),
	})
	for p.HasMorePages() {
		page, err := p.NextPage(t.Context())
		check(t, err == nil, "list user tags: %v", err)
		for _, tg := range page.Tags {
			out = append(out, aws.ToString(tg.Key)+"="+aws.ToString(tg.Value))
		}
	}
	return out
}

func TestUsersCarryTags(t *testing.T) {
	ctx := t.Context()
	url := startApp(t, t.TempDir(), nil)
	c := iamClient(url, rootCreds())

	created, err := c.CreateUser(ctx, &iam.CreateUserInput{
		UserName: aws.String("dev"),
		Tags:     []iamtypes.Tag{tag("Team", "core"), tag("Env", "dev")},
	})
	check(t, err == nil, "create user: %v", err)
	check(t, len(created.User.Tags) == 2, "created user's tags = %+v", created.User.Tags)

	got, err := c.GetUser(ctx, &iam.GetUserInput{UserName: aws.String("dev")})
	check(t, err == nil, "get user: %v", err)
	check(t, len(got.User.Tags) == 2 && aws.ToString(got.User.Tags[0].Key) == "Env",
		"user's tags = %+v", got.User.Tags)

	// Keys are not case sensitive: env replaces Env, key and value.
	_, err = c.TagUser(ctx, &iam.TagUserInput{
		UserName: aws.String("dev"), Tags: []iamtypes.Tag{tag("env", "prod"), tag("Cost", "")},
	})
	check(t, err == nil, "tag user: %v", err)
	check(t, fmt.Sprint(userTags(t, c)) == "[Cost= env=prod Team=core]",
		"tags = %v", userTags(t, c))

	_, err = c.UntagUser(ctx, &iam.UntagUserInput{
		UserName: aws.String("dev"), TagKeys: []string{"TEAM", "absent"},
	})
	check(t, err == nil, "untag user: %v", err)
	check(t, fmt.Sprint(userTags(t, c)) == "[Cost= env=prod]",
		"tags after untag = %v", userTags(t, c))

	// ListUsers does not report tags.
	listed, err := c.ListUsers(ctx, &iam.ListUsersInput{})
	check(t, err == nil, "list users: %v", err)
	check(t, len(listed.Users) == 1 && listed.Users[0].Tags == nil, "listed = %+v", listed.Users)
}

func TestTagRules(t *testing.T) {
	ctx := t.Context()
	url := startApp(t, t.TempDir(), nil)
	c := iamClient(url, rootCreds())
	_, err := c.CreateUser(ctx, &iam.CreateUserInput{UserName: aws.String("dev")})
	check(t, err == nil, "create user: %v", err)

	for name, tags := range map[string][]iamtypes.Tag{
		"reserved key":   {tag("aws:team", "core")},
		"reserved value": {tag("team", "AWS:core")},
		"duplicate key":  {tag("team", "a"), tag("Team", "b")},
	} {
		_, err = c.TagUser(ctx, &iam.TagUserInput{UserName: aws.String("dev"), Tags: tags})
		check(t, err != nil, "%s: tag user succeeded", name)
		requireCode(t, err, "InvalidInput")
	}

	_, err = c.TagUser(ctx, &iam.TagUserInput{
		UserName: aws.String("dev"), Tags: []iamtypes.Tag{tag("bad key!", "x")},
	})
	requireCode(t, err, "ValidationError")

	_, err = c.CreateUser(ctx, &iam.CreateUserInput{
		UserName:            aws.String("bounded"),
		PermissionsBoundary: aws.String("arn:aws:iam::aws:policy/PowerUserAccess"),
	})
	requireCode(t, err, "InvalidInput")
}

func TestAUserCarriesAtMostFiftyTags(t *testing.T) {
	ctx := t.Context()
	url := startApp(t, t.TempDir(), nil)
	c := iamClient(url, rootCreds())

	fifty := make([]iamtypes.Tag, 0, 51)
	for i := range 50 {
		fifty = append(fifty, tag(fmt.Sprintf("k%02d", i), "v"))
	}
	_, err := c.CreateUser(ctx, &iam.CreateUserInput{UserName: aws.String("dev"), Tags: fifty})
	check(t, err == nil, "create user with 50 tags: %v", err)

	_, err = c.TagUser(ctx, &iam.TagUserInput{
		UserName: aws.String("dev"), Tags: []iamtypes.Tag{tag("one-more", "v")},
	})
	requireCode(t, err, "LimitExceeded")
	check(t, len(userTags(t, c)) == 50, "a refused TagUser set tags")

	// Replacing a tag the IAM user has is no new tag.
	_, err = c.TagUser(ctx, &iam.TagUserInput{
		UserName: aws.String("dev"), Tags: []iamtypes.Tag{tag("K00", "w")},
	})
	check(t, err == nil, "replace a tag at the limit: %v", err)

	_, err = c.CreateUser(ctx, &iam.CreateUserInput{
		UserName: aws.String("too-many"), Tags: append(fifty, tag("k50", "v")),
	})
	requireCode(t, err, "ValidationError")
}
