//go:build e2e

package e2e

import (
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/iam/types"
)

// userARN is an IAM user's ARN: arn:aws:iam::<account>:user<path><name>
// (IAM User Guide, IAM identifiers, IAM ARNs).
func userARN(account, path, name string) string {
	return "arn:aws:iam::" + account + ":user" + path + name
}

// requireUser checks the fields every User carries (types.User).
func requireUser(t *testing.T, u *types.User, account, path, name string) {
	t.Helper()
	if u == nil {
		t.Fatal("no user returned")
	}
	requireEqual(t, aws.ToString(u.UserName), name, "UserName")
	requireEqual(t, aws.ToString(u.Path), path, "Path")
	requireEqual(t, aws.ToString(u.Arn), userARN(account, path, name), "Arn")
	requireMatch(t, userIDPattern, aws.ToString(u.UserId), "UserId")
	if u.CreateDate == nil {
		t.Fatal("no CreateDate")
	}
}

func TestCreateUser(t *testing.T) {
	_, c := rootIAM(t)
	before := time.Now()

	out, err := c.CreateUser(t.Context(), &iam.CreateUserInput{UserName: aws.String("dev")})
	requireNoErr(t, err, "create user")

	// The path defaults to a slash (CreateUserInput.Path).
	requireUser(t, out.User, defaultAccountID, "/", "dev")
	requireRecent(t, out.User.CreateDate, before, time.Now(), "CreateDate")

	t.Run("GetUser agrees", func(t *testing.T) {
		got, err := c.GetUser(t.Context(), &iam.GetUserInput{UserName: aws.String("dev")})
		requireNoErr(t, err, "get user")
		requireUser(t, got.User, defaultAccountID, "/", "dev")
		requireEqual(t, aws.ToString(got.User.UserId), aws.ToString(out.User.UserId), "UserId")
		requireEqual(t, got.User.CreateDate.Unix(), out.User.CreateDate.Unix(), "CreateDate")
	})

	t.Run("ListUsers agrees", func(t *testing.T) {
		got, err := c.ListUsers(t.Context(), &iam.ListUsersInput{})
		requireNoErr(t, err, "list users")
		requireEqual(t, len(got.Users), 1, "user count")
		requireUser(t, &got.Users[0], defaultAccountID, "/", "dev")
		requireEqual(t, got.IsTruncated, false, "IsTruncated")
	})
}

func TestCreateUserWithPath(t *testing.T) {
	_, c := rootIAM(t)
	path := "/division_abc/subdivision_xyz/"

	out, err := c.CreateUser(t.Context(), &iam.CreateUserInput{
		UserName: aws.String("pathed"),
		Path:     aws.String(path),
	})
	requireNoErr(t, err, "create user")
	requireUser(t, out.User, defaultAccountID, path, "pathed")

	got, err := c.GetUser(t.Context(), &iam.GetUserInput{UserName: aws.String("pathed")})
	requireNoErr(t, err, "get user")
	requireUser(t, got.User, defaultAccountID, path, "pathed")
}

func TestCreateUserNameCharacters(t *testing.T) {
	// userNameType: 1 to 64 characters of [\w+=,.@-].
	_, c := rootIAM(t)
	for _, name := range []string{"a", "A_b+c=d,e.f@g-h", strings.Repeat("n", 64)} {
		createUser(t, c, name)
	}
}

func TestDuplicateUser(t *testing.T) {
	_, c := rootIAM(t)
	createUser(t, c, "Builder")

	t.Run("same name", func(t *testing.T) {
		err := errOf(c.CreateUser(t.Context(), &iam.CreateUserInput{
			UserName: aws.String("Builder"),
		}))
		requireAs[*types.EntityAlreadyExistsException](t, err)
	})

	// CreateUserInput.UserName: names are not distinguished by case; "you
	// cannot create resources named both MyResource and myresource".
	t.Run("other case", func(t *testing.T) {
		err := errOf(c.CreateUser(t.Context(), &iam.CreateUserInput{
			UserName: aws.String("builder"),
		}))
		requireAs[*types.EntityAlreadyExistsException](t, err)
	})

	// Neither attempt added a user.
	got, err := c.ListUsers(t.Context(), &iam.ListUsersInput{})
	requireNoErr(t, err, "list users")
	requireEqual(t, len(got.Users), 1, "user count")
}

func TestInvalidUserInput(t *testing.T) {
	// userNameType is 1 to 64 characters matching [\w+=,.@-]+, and pathType is
	// "/" or a string of !-~ that begins and ends with "/", at most
	// 512 long (botocore iam 2010-05-08). The Go SDK checks neither, so the
	// service sees them, and AWS answers constraint failures with
	// ValidationError (Common Error Types).
	_, c := rootIAM(t)

	tests := []struct {
		name string
		in   iam.CreateUserInput
	}{
		{"empty name", iam.CreateUserInput{UserName: aws.String("")}},
		{"name with a space", iam.CreateUserInput{UserName: aws.String("has space")}},
		{"name with a slash", iam.CreateUserInput{UserName: aws.String("a/b")}},
		{"name with a star", iam.CreateUserInput{UserName: aws.String("a*b")}},
		{"name of 65", iam.CreateUserInput{UserName: aws.String(strings.Repeat("n", 65))}},
		{"path without slashes", iam.CreateUserInput{
			UserName: aws.String("p1"), Path: aws.String("division"),
		}},
		{"path without a trailing slash", iam.CreateUserInput{
			UserName: aws.String("p2"), Path: aws.String("/division"),
		}},
		{"path without a leading slash", iam.CreateUserInput{
			UserName: aws.String("p3"), Path: aws.String("division/"),
		}},
		{"path with a space", iam.CreateUserInput{
			UserName: aws.String("p4"), Path: aws.String("/a b/"),
		}},
		{"path of 513", iam.CreateUserInput{
			UserName: aws.String("p5"), Path: aws.String("/" + strings.Repeat("p", 511) + "/"),
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			requireCode(t, errOf(c.CreateUser(t.Context(), &tt.in)), codeValidation)
		})
	}

	got, err := c.ListUsers(t.Context(), &iam.ListUsersInput{})
	requireNoErr(t, err, "list users")
	requireEqual(t, len(got.Users), 0, "users created by invalid requests")

	// existingUserNameType has the same pattern.
	t.Run("GetUser name with a space", func(t *testing.T) {
		err := errOf(c.GetUser(t.Context(), &iam.GetUserInput{UserName: aws.String("has space")}))
		requireCode(t, err, codeValidation)
	})
}

func TestUnknownUser(t *testing.T) {
	// NoSuchEntity is in the errors of every operation below (botocore iam).
	_, c := rootIAM(t)
	name := aws.String("nobody")

	t.Run("GetUser", func(t *testing.T) {
		requireAs[*types.NoSuchEntityException](t,
			errOf(c.GetUser(t.Context(), &iam.GetUserInput{UserName: name})))
	})
	t.Run("DeleteUser", func(t *testing.T) {
		requireAs[*types.NoSuchEntityException](t,
			errOf(c.DeleteUser(t.Context(), &iam.DeleteUserInput{UserName: name})))
	})
	t.Run("CreateAccessKey", func(t *testing.T) {
		requireAs[*types.NoSuchEntityException](t,
			errOf(c.CreateAccessKey(t.Context(), &iam.CreateAccessKeyInput{UserName: name})))
	})
	t.Run("ListAccessKeys", func(t *testing.T) {
		requireAs[*types.NoSuchEntityException](t,
			errOf(c.ListAccessKeys(t.Context(), &iam.ListAccessKeysInput{UserName: name})))
	})
}

func TestDeleteUser(t *testing.T) {
	_, c := rootIAM(t)
	createUser(t, c, "doomed")
	createUser(t, c, "kept")

	_, err := c.DeleteUser(t.Context(), &iam.DeleteUserInput{UserName: aws.String("doomed")})
	requireNoErr(t, err, "delete user")

	requireAs[*types.NoSuchEntityException](t, errOf(c.GetUser(t.Context(),
		&iam.GetUserInput{UserName: aws.String("doomed")})))

	got, err := c.ListUsers(t.Context(), &iam.ListUsersInput{})
	requireNoErr(t, err, "list users")
	requireEqual(t, len(got.Users), 1, "user count")
	requireEqual(t, aws.ToString(got.Users[0].UserName), "kept", "remaining user")

	t.Run("name is free again", func(t *testing.T) {
		createUser(t, c, "doomed")
	})
}

func TestDeleteUserWithKeys(t *testing.T) {
	// DeleteUser: the access keys must be deleted first "or the deletion
	// fails"; DeleteConflict is in its errors.
	_, c := rootIAM(t)
	key := userWithKey(t, c, "holder")

	err := errOf(c.DeleteUser(t.Context(), &iam.DeleteUserInput{UserName: aws.String("holder")}))
	requireAs[*types.DeleteConflictException](t, err)

	// The user and the key are still there.
	_, err = c.GetUser(t.Context(), &iam.GetUserInput{UserName: aws.String("holder")})
	requireNoErr(t, err, "get user after refused delete")

	_, err = c.DeleteAccessKey(t.Context(), &iam.DeleteAccessKeyInput{
		UserName:    aws.String("holder"),
		AccessKeyId: aws.String(key.AccessKeyID),
	})
	requireNoErr(t, err, "delete access key")

	_, err = c.DeleteUser(t.Context(), &iam.DeleteUserInput{UserName: aws.String("holder")})
	requireNoErr(t, err, "delete user once its keys are gone")
}

func TestListUsersPathPrefix(t *testing.T) {
	// ListUsersInput.PathPrefix: lists the users whose path starts with it.
	_, c := rootIAM(t)
	for name, path := range map[string]string{
		"root1": "/",
		"eng1":  "/eng/",
		"eng2":  "/eng/backend/",
		"ops1":  "/ops/",
	} {
		_, err := c.CreateUser(t.Context(), &iam.CreateUserInput{
			UserName: aws.String(name), Path: aws.String(path),
		})
		requireNoErr(t, err, "create user "+name)
	}

	tests := []struct {
		prefix string
		want   []string
	}{
		{"/", []string{"eng1", "eng2", "ops1", "root1"}},
		{"/eng/", []string{"eng1", "eng2"}},
		{"/eng/backend/", []string{"eng2"}},
		{"/none/", nil},
	}
	for _, tt := range tests {
		t.Run(tt.prefix, func(t *testing.T) {
			out, err := c.ListUsers(t.Context(), &iam.ListUsersInput{
				PathPrefix: aws.String(tt.prefix),
			})
			requireNoErr(t, err, "list users")
			requireSameNames(t, userNames(out.Users), tt.want)
		})
	}
}

func userNames(users []types.User) []string {
	names := make([]string, 0, len(users))
	for _, u := range users {
		names = append(names, aws.ToString(u.UserName))
	}
	return names
}

// requireSameNames fails unless got and want hold the same names, in any
// order: no IAM listing documents its order.
func requireSameNames(t *testing.T, got, want []string) {
	t.Helper()
	g := slices.Clone(got)
	w := slices.Clone(want)
	slices.Sort(g)
	slices.Sort(w)
	if !slices.Equal(g, w) {
		t.Fatalf("got %v, want %v", got, want)
	}
}
