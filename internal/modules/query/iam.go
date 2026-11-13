package query

import (
	"errors"

	"github.com/gasmod/gas"

	"tule.dev/identity/internal/contracts"
	"tule.dev/identity/internal/queryapi"
)

// target is whom an operation with an optional UserName acts on: the named
// IAM user, or, when the request names none, the caller.
type target struct {
	name string
	// root is set when the request names no user and the caller is the root
	// user, which the operation then acts on itself.
	root bool
}

// requestedUser reads the optional UserName of GetUser, ListUserTags and the
// access key operations. Without one, the operation acts on the caller, as
// IAM determines the IAM user from the signing key: an IAM user's own name, or
// the root user itself. A role session must name a user, as AWS requires of
// temporary credentials.
func requestedUser(c *call) (target, error) {
	name, err := queryapi.ExistingUserName.Optional(c.params, "UserName")
	if err != nil {
		return target{}, err
	}
	if _, set := c.params.Get("UserName"); set {
		return target{name: name}, nil
	}
	switch c.caller.Kind {
	case contracts.PrincipalUser:
		return target{name: c.caller.UserName}, nil
	case contracts.PrincipalRoot:
		return target{root: true}, nil
	default:
		return target{}, queryapi.ErrValidation(
			"Must specify userName when calling with non-User credentials")
	}
}

// userError maps the store's user and key sentinels to the error documents
// that name the IAM user or key.
func userError(err error, userName, keyID string) error {
	switch {
	case errors.Is(err, contracts.ErrUserNotFound):
		return queryapi.ErrNoSuchUser(userName)
	case errors.Is(err, contracts.ErrUserExists):
		return queryapi.ErrUserExists(userName)
	case errors.Is(err, contracts.ErrAccessKeyNotFound):
		return queryapi.ErrNoSuchAccessKey(keyID)
	}
	return err
}

func wireUser(u *contracts.User) queryapi.User {
	out := queryapi.User{
		Path:       u.Path,
		UserName:   u.Name,
		UserID:     u.ID,
		Arn:        u.ARN,
		CreateDate: queryapi.Stamp(u.CreateDate),
	}
	if len(u.Tags) > 0 {
		tags := queryapi.ListOf(wireTags(u.Tags))
		out.Tags = &tags
	}
	return out
}

func (m *Module) createUser(ctx gas.Context, c *call) error {
	name, err := queryapi.UserName.Required(c.params, "UserName")
	if err != nil {
		return err
	}
	path, err := queryapi.Path.Optional(c.params, "Path")
	if err != nil {
		return err
	}
	if path == "" {
		path = "/"
	}
	tags, _, err := c.requestTags()
	if err != nil {
		return err
	}
	// A permissions boundary is refused rather than answered as though it
	// were kept: there are no policies to bound.
	if c.params.HasPrefix("PermissionsBoundary") {
		return queryapi.ErrInvalidInput(
			"This service does not support PermissionsBoundary on users.")
	}
	account := c.caller.AccountID
	if err = m.authorize(ctx, c); err != nil {
		return err
	}

	u, err := m.store.CreateUser(ctx, account, name, path, tags)
	if err != nil {
		return userError(err, name, "")
	}
	// CreateUser returns the IAM user as GetUser would, tags included.
	u.Tags = tags
	return write(ctx, c, queryapi.UserResult{User: wireUser(u)})
}

func (m *Module) getUser(ctx gas.Context, c *call) error {
	t, err := requestedUser(c)
	if err != nil {
		return err
	}
	if err = m.authorize(ctx, c); err != nil {
		return err
	}

	if t.root {
		// The root user, as the policy variables reference describes it:
		// its ID is the account ID, and it has no user name or path.
		created, rErr := m.store.RootCreateDate(ctx)
		if rErr != nil {
			return rErr
		}
		return write(ctx, c, queryapi.UserResult{User: queryapi.User{
			UserID:     c.caller.AccountID,
			Arn:        c.caller.ARN,
			CreateDate: queryapi.Stamp(created),
		}})
	}
	u, err := m.store.GetUser(ctx, c.caller.AccountID, t.name)
	if err != nil {
		return userError(err, t.name, "")
	}
	return write(ctx, c, queryapi.UserResult{User: wireUser(u)})
}

func (m *Module) listUsers(ctx gas.Context, c *call) error {
	prefix, err := queryapi.PathPrefix.Optional(c.params, "PathPrefix")
	if err != nil {
		return err
	}
	if prefix == "" {
		prefix = "/"
	}
	marker, maxItems, err := queryapi.Page(c.params)
	if err != nil {
		return err
	}
	if err = m.authorize(ctx, c); err != nil {
		return err
	}

	page, err := m.store.ListUsers(ctx, contracts.ListUsersInput{
		AccountID:  c.caller.AccountID,
		PathPrefix: prefix,
		Marker:     marker,
		MaxItems:   maxItems,
	})
	if err != nil {
		return err
	}
	users := make([]queryapi.User, 0, len(page.Items))
	for i := range page.Items {
		users = append(users, wireUser(&page.Items[i]))
	}
	return write(ctx, c, queryapi.ListUsersResult{
		Users:       queryapi.ListOf(users),
		IsTruncated: page.Marker != "",
		Marker:      page.Marker,
	})
}

func (m *Module) deleteUser(ctx gas.Context, c *call) error {
	name, err := queryapi.ExistingUserName.Required(c.params, "UserName")
	if err != nil {
		return err
	}
	if err = m.authorize(ctx, c); err != nil {
		return err
	}

	if err = m.store.DeleteUser(ctx, c.caller.AccountID, name); err != nil {
		return userError(err, name, "")
	}
	return write(ctx, c, nil)
}
