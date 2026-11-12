package query

import (
	"github.com/gasmod/gas"

	"tule.dev/identity/internal/contracts"
	"tule.dev/identity/internal/queryapi"
)

func (m *Module) createAccessKey(ctx gas.Context, c *call) error {
	t, err := requestedUser(c)
	if err != nil {
		return err
	}
	if err = authorize(c, t.resource(c)); err != nil {
		return err
	}
	if t.root {
		return queryapi.ErrRootAccessKey()
	}

	k, err := m.store.CreateAccessKey(ctx, c.caller.AccountID, t.name)
	if err != nil {
		return userError(err, t.name, "")
	}
	return write(ctx, c, queryapi.CreateAccessKeyResult{AccessKey: queryapi.AccessKey{
		UserName:        k.UserName,
		AccessKeyID:     k.ID,
		Status:          k.Status,
		SecretAccessKey: k.SecretAccessKey,
		CreateDate:      queryapi.Stamp(k.CreateDate),
	}})
}

func (m *Module) listAccessKeys(ctx gas.Context, c *call) error {
	t, err := requestedUser(c)
	if err != nil {
		return err
	}
	marker, maxItems, err := queryapi.Page(c.params)
	if err != nil {
		return err
	}
	if err = authorize(c, t.resource(c)); err != nil {
		return err
	}

	if t.root {
		return m.listRootAccessKey(ctx, c, marker)
	}
	page, err := m.store.ListAccessKeys(ctx, contracts.ListAccessKeysInput{
		AccountID: c.caller.AccountID,
		UserName:  t.name,
		Marker:    marker,
		MaxItems:  maxItems,
	})
	if err != nil {
		return userError(err, t.name, "")
	}
	keys := make([]queryapi.AccessKeyMetadata, 0, len(page.Items))
	for _, k := range page.Items {
		keys = append(keys, queryapi.AccessKeyMetadata{
			UserName:    k.UserName,
			AccessKeyID: k.ID,
			Status:      k.Status,
			CreateDate:  queryapi.Stamp(k.CreateDate),
		})
	}
	return write(ctx, c, queryapi.ListAccessKeysResult{
		AccessKeyMetadata: queryapi.ListOf(keys),
		IsTruncated:       page.Marker != "",
		Marker:            page.Marker,
	})
}

// listRootAccessKey lists the root user's one key, the configured one, which
// is always Active. It fits on one page, so no marker resumes it.
func (m *Module) listRootAccessKey(ctx gas.Context, c *call, marker string) error {
	if marker != "" {
		return contracts.ErrInvalidMarker
	}
	created, err := m.store.RootCreateDate(ctx)
	if err != nil {
		return err
	}
	return write(ctx, c, queryapi.ListAccessKeysResult{
		AccessKeyMetadata: queryapi.ListOf([]queryapi.AccessKeyMetadata{{
			AccessKeyID: c.caller.AccessKeyID,
			Status:      contracts.StatusActive,
			CreateDate:  queryapi.Stamp(created),
		}}),
	})
}

// keyStatuses are the values statusType takes. Expired is one, but not one
// a key can be set to.
var keyStatuses = []string{contracts.StatusActive, contracts.StatusInactive, "Expired"}

func (m *Module) updateAccessKey(ctx gas.Context, c *call) error {
	keyID, err := queryapi.AccessKeyID.Required(c.params, "AccessKeyId")
	if err != nil {
		return err
	}
	status, err := queryapi.Enum(c.params, "Status", keyStatuses...)
	if err != nil {
		return err
	}
	if status != contracts.StatusActive && status != contracts.StatusInactive {
		return queryapi.ErrInvalidInput("An access key's status can only be set to " +
			contracts.StatusActive + " or " + contracts.StatusInactive + ".")
	}
	t, err := requestedUser(c)
	if err != nil {
		return err
	}
	if err = authorize(c, t.resource(c)); err != nil {
		return err
	}
	if t.root {
		return queryapi.ErrRootAccessKey()
	}

	if err = m.store.UpdateAccessKey(ctx, c.caller.AccountID, t.name, keyID, status); err != nil {
		return userError(err, t.name, keyID)
	}
	return write(ctx, c, nil)
}

func (m *Module) deleteAccessKey(ctx gas.Context, c *call) error {
	keyID, err := queryapi.AccessKeyID.Required(c.params, "AccessKeyId")
	if err != nil {
		return err
	}
	t, err := requestedUser(c)
	if err != nil {
		return err
	}
	if err = authorize(c, t.resource(c)); err != nil {
		return err
	}
	if t.root {
		return queryapi.ErrRootAccessKey()
	}

	if err = m.store.DeleteAccessKey(ctx, c.caller.AccountID, t.name, keyID); err != nil {
		return userError(err, t.name, keyID)
	}
	return write(ctx, c, nil)
}

// notApplicable is what GetAccessKeyLastUsed reports as the service and
// region of a key never used.
const notApplicable = "N/A"

func (m *Module) getAccessKeyLastUsed(ctx gas.Context, c *call) error {
	keyID, err := queryapi.AccessKeyID.Required(c.params, "AccessKeyId")
	if err != nil {
		return err
	}
	if err = authorize(c, c.caller.ARN); err != nil {
		return err
	}

	used, err := m.store.GetAccessKeyLastUsed(ctx, c.caller.AccountID, keyID)
	if err != nil {
		return userError(err, "", keyID)
	}
	out := queryapi.GetAccessKeyLastUsedResult{
		UserName: used.UserName,
		AccessKeyLastUsed: queryapi.AccessKeyLastUsed{
			ServiceName: notApplicable,
			Region:      notApplicable,
		},
	}
	if !used.LastUsed.IsZero() {
		out.AccessKeyLastUsed = queryapi.AccessKeyLastUsed{
			LastUsedDate: queryapi.Stamp(used.LastUsed),
			ServiceName:  used.Service,
			Region:       used.Region,
		}
	}
	return write(ctx, c, out)
}
