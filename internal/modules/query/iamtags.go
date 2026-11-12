package query

import (
	"github.com/gasmod/gas"

	"tule.dev/identity/internal/contracts"
	"tule.dev/identity/internal/queryapi"
)

func wireTags(tags []contracts.Tag) []queryapi.Tag {
	out := make([]queryapi.Tag, 0, len(tags))
	for _, t := range tags {
		out = append(out, queryapi.Tag{Key: t.Key, Value: t.Value})
	}
	return out
}

func (m *Module) tagUser(ctx gas.Context, c *call) error {
	name, err := queryapi.ExistingUserName.Required(c.params, "UserName")
	if err != nil {
		return err
	}
	tags, set, err := queryapi.Tags(c.params, "Tags")
	if err != nil {
		return err
	}
	if !set {
		return queryapi.ErrValidation("1 validation error detected: Value null at 'tags' " +
			"failed to satisfy constraint: Member must not be null")
	}
	if err = authorize(c, userResource(c.caller.AccountID, name)); err != nil {
		return err
	}

	if err = m.store.TagUser(ctx, c.caller.AccountID, name, tags); err != nil {
		return userError(err, name, "")
	}
	return write(ctx, c, nil)
}

func (m *Module) untagUser(ctx gas.Context, c *call) error {
	name, err := queryapi.ExistingUserName.Required(c.params, "UserName")
	if err != nil {
		return err
	}
	keys, err := queryapi.TagKeys(c.params, "TagKeys")
	if err != nil {
		return err
	}
	if err = authorize(c, userResource(c.caller.AccountID, name)); err != nil {
		return err
	}

	if err = m.store.UntagUser(ctx, c.caller.AccountID, name, keys); err != nil {
		return userError(err, name, "")
	}
	return write(ctx, c, nil)
}

func (m *Module) listUserTags(ctx gas.Context, c *call) error {
	name, err := queryapi.ExistingUserName.Required(c.params, "UserName")
	if err != nil {
		return err
	}
	marker, maxItems, err := queryapi.Page(c.params)
	if err != nil {
		return err
	}
	if err = authorize(c, userResource(c.caller.AccountID, name)); err != nil {
		return err
	}

	page, err := m.store.ListUserTags(ctx, contracts.ListUserTagsInput{
		AccountID: c.caller.AccountID,
		UserName:  name,
		Marker:    marker,
		MaxItems:  maxItems,
	})
	if err != nil {
		return userError(err, name, "")
	}
	return write(ctx, c, queryapi.ListUserTagsResult{
		Tags:        queryapi.ListOf(wireTags(page.Items)),
		IsTruncated: page.Marker != "",
		Marker:      page.Marker,
	})
}
