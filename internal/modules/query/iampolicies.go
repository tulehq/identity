package query

import (
	"errors"
	"fmt"

	"github.com/gasmod/gas"
	"tule.dev/policy"

	"tule.dev/identity/internal/contracts"
	"tule.dev/identity/internal/queryapi"
)

// documentKind is what a policy document is for: an identity policy, which
// names no principal, or a role's trust policy, which must.
type documentKind int

const (
	identityDocument documentKind = iota
	trustDocument
)

// policyDocument reads the required policy document field and checks it: the
// model's constraint, then the grammar of its kind, through tule.dev/policy's
// ParseIdentity or ParseTrust, whose ParseError is answered as
// MalformedPolicyDocument. sizeLimit, when not zero, bounds its size
// as IAM counts it, white space excluded, with LimitExceeded and the quota
// name.
func policyDocument(
	c *call,
	field string,
	kind documentKind,
	sizeLimit int,
	quota string,
) (string, error) {
	doc, err := queryapi.PolicyDocument.Required(c.params, field)
	if err != nil {
		return "", err
	}
	if _, err = parseDocument(doc, kind); err != nil {
		var pe *policy.ParseError
		if errors.As(err, &pe) {
			return "", queryapi.ErrMalformedPolicy(pe.Error())
		}
		return "", fmt.Errorf("query: parse the policy document: %w", err)
	}
	if sizeLimit > 0 && contracts.PolicySize(doc) > sizeLimit {
		return "", queryapi.ErrLimitExceeded(
			fmt.Sprintf("Cannot exceed quota for %s: %d", quota, sizeLimit))
	}
	return doc, nil
}

// parseDocument parses a document of the kind: an identity policy, which
// may name no principal, or a trust policy, every statement of which must.
func parseDocument(doc string, kind documentKind) (*policy.Policy, error) {
	if kind == trustDocument {
		//nolint:wrapcheck // the *policy.ParseError is what callers read
		return policy.ParseTrust([]byte(doc))
	}
	//nolint:wrapcheck // as above
	return policy.ParseIdentity([]byte(doc))
}

// policyARN reads the required PolicyArn and checks that it names a managed
// policy.
func policyARN(c *call) (string, error) {
	arn, err := queryapi.PolicyARN.Required(c.params, "PolicyArn")
	if err != nil {
		return "", err
	}
	if _, _, _, ok := contracts.ParsePolicyARN(arn); !ok {
		return "", queryapi.ErrInvalidInput("ARN " + arn + " is not valid.")
	}
	return arn, nil
}

// policyError maps the store's policy sentinels to the error documents that
// name the policy.
func policyError(err error, arn, name, versionID string) error {
	switch {
	case errors.Is(err, contracts.ErrPolicyNotFound),
		errors.Is(err, contracts.ErrPolicyNotAttached):
		return queryapi.ErrNoSuchEntity("Policy " + arn + " was not found.")
	case errors.Is(err, contracts.ErrPolicyExists):
		return queryapi.ErrEntityAlreadyExists("A policy called " + name +
			" already exists. Duplicate names are not allowed.")
	case errors.Is(err, contracts.ErrPolicyVersionNotFound):
		return queryapi.ErrNoSuchEntity("Policy " + arn + " version " + versionID +
			" does not exist or is not attachable.")
	}
	return err
}

// pathParam reads an optional path or path prefix, "/" when the request
// sets none.
func pathParam(c *call, rule queryapi.Rule, field string) (string, error) {
	p, err := rule.Optional(c.params, field)
	if p == "" && err == nil {
		p = "/"
	}
	return p, err
}

func wirePolicy(p *contracts.ManagedPolicy, full bool) queryapi.Policy {
	out := queryapi.Policy{
		PolicyName:       p.Name,
		PolicyID:         p.ID,
		Arn:              p.ARN,
		Path:             p.Path,
		DefaultVersionID: p.DefaultVersionID,
		CreateDate:       queryapi.Stamp(p.CreateDate),
		UpdateDate:       queryapi.Stamp(p.UpdateDate),
		AttachmentCount:  p.AttachmentCount,
		IsAttachable:     true,
	}
	if full {
		out.Description = p.Description
		if len(p.Tags) > 0 {
			tags := queryapi.ListOf(wireTags(p.Tags))
			out.Tags = &tags
		}
	}
	return out
}

func wireVersion(v *contracts.PolicyVersion) queryapi.PolicyVersion {
	out := queryapi.PolicyVersion{
		VersionID:        v.VersionID,
		CreateDate:       queryapi.Stamp(v.CreateDate),
		IsDefaultVersion: v.IsDefault,
	}
	if v.Document != "" {
		out.Document = queryapi.EncodeDocument(v.Document)
	}
	return out
}

func (m *Module) createPolicy(ctx gas.Context, c *call) error {
	name, err := queryapi.PolicyName.Required(c.params, "PolicyName")
	if err != nil {
		return err
	}
	path, err := pathParam(c, queryapi.PolicyPath, "Path")
	if err != nil {
		return err
	}
	doc, err := policyDocument(c, "PolicyDocument", identityDocument,
		contracts.MaxManagedPolicySize, "PolicySize")
	if err != nil {
		return err
	}
	description, err := queryapi.PolicyDescription.Optional(c.params, "Description")
	if err != nil {
		return err
	}
	tags, _, err := c.requestTags()
	if err != nil {
		return err
	}
	if err = m.authorize(ctx, c); err != nil {
		return err
	}

	p, err := m.store.CreatePolicy(ctx, contracts.CreatePolicyInput{
		AccountID:   c.caller.AccountID,
		Name:        name,
		Path:        path,
		Description: description,
		Document:    doc,
		Tags:        tags,
	})
	if err != nil {
		return policyError(err, "", name, "")
	}
	return write(ctx, c, queryapi.PolicyResult{Policy: wirePolicy(p, true)})
}

func (m *Module) getPolicy(ctx gas.Context, c *call) error {
	arn, err := policyARN(c)
	if err != nil {
		return err
	}
	if err = m.authorize(ctx, c); err != nil {
		return err
	}

	p, err := m.store.GetPolicy(ctx, c.caller.AccountID, arn)
	if err != nil {
		return policyError(err, arn, "", "")
	}
	return write(ctx, c, queryapi.PolicyResult{Policy: wirePolicy(p, true)})
}

// policyUsages are the values of PolicyUsageType. No policy is used as a
// permissions boundary here, so listing by that usage lists none.
var policyUsages = []string{"PermissionsPolicy", "PermissionsBoundary"}

// listPoliciesInput reads the ListPolicies parameters, and whether the
// request asks only for policies used as permissions boundaries.
func listPoliciesInput(c *call) (in contracts.ListPoliciesInput, boundaries bool, err error) {
	in.AccountID = c.caller.AccountID
	if in.Scope, err = queryapi.OptionalEnum(
		c.params,
		"Scope",
		contracts.PolicyScopeAll,
		contracts.PolicyScopeAll,
		contracts.PolicyScopeAWS,
		contracts.PolicyScopeLocal,
	); err != nil {
		return in, false, err
	}
	if in.OnlyAttached, err = queryapi.Bool(c.params, "OnlyAttached"); err != nil {
		return in, false, err
	}
	if in.PathPrefix, err = pathParam(c, queryapi.PolicyPath, "PathPrefix"); err != nil {
		return in, false, err
	}
	usage, err := queryapi.OptionalEnum(c.params, "PolicyUsageFilter", "", policyUsages...)
	if err != nil {
		return in, false, err
	}
	in.Marker, in.MaxItems, err = queryapi.Page(c.params)
	return in, usage == "PermissionsBoundary", err
}

func (m *Module) listPolicies(ctx gas.Context, c *call) error {
	in, boundaries, err := listPoliciesInput(c)
	if err != nil {
		return err
	}
	if err = m.authorize(ctx, c); err != nil {
		return err
	}

	page := &contracts.Page[contracts.ManagedPolicy]{}
	switch {
	case !boundaries:
		if page, err = m.store.ListPolicies(ctx, in); err != nil {
			return err
		}
	case in.Marker != "":
		return contracts.ErrInvalidMarker
	}
	policies := make([]queryapi.Policy, 0, len(page.Items))
	for i := range page.Items {
		policies = append(policies, wirePolicy(&page.Items[i], false))
	}
	return write(ctx, c, queryapi.ListPoliciesResult{
		Policies:    queryapi.ListOf(policies),
		IsTruncated: page.Marker != "",
		Marker:      page.Marker,
	})
}

func (m *Module) deletePolicy(ctx gas.Context, c *call) error {
	arn, err := policyARN(c)
	if err != nil {
		return err
	}
	if err = m.authorize(ctx, c); err != nil {
		return err
	}

	if err = m.store.DeletePolicy(ctx, c.caller.AccountID, arn); err != nil {
		return policyError(err, arn, "", "")
	}
	return write(ctx, c, nil)
}

func (m *Module) createPolicyVersion(ctx gas.Context, c *call) error {
	arn, err := policyARN(c)
	if err != nil {
		return err
	}
	doc, err := policyDocument(c, "PolicyDocument", identityDocument,
		contracts.MaxManagedPolicySize, "PolicySize")
	if err != nil {
		return err
	}
	setAsDefault, err := queryapi.Bool(c.params, "SetAsDefault")
	if err != nil {
		return err
	}
	if err = m.authorize(ctx, c); err != nil {
		return err
	}

	v, err := m.store.CreatePolicyVersion(ctx, c.caller.AccountID, arn, doc, setAsDefault)
	if err != nil {
		return policyError(err, arn, "", "")
	}
	return write(ctx, c, queryapi.PolicyVersionResult{PolicyVersion: wireVersion(v)})
}

// versionParams reads the PolicyArn and VersionId of the version operations.
func versionParams(c *call) (arn, versionID string, err error) {
	if arn, err = policyARN(c); err != nil {
		return "", "", err
	}
	if versionID, err = queryapi.PolicyVersionID.Required(c.params, "VersionId"); err != nil {
		return "", "", err
	}
	return arn, versionID, nil
}

func (m *Module) getPolicyVersion(ctx gas.Context, c *call) error {
	arn, versionID, err := versionParams(c)
	if err != nil {
		return err
	}
	if err = m.authorize(ctx, c); err != nil {
		return err
	}

	v, err := m.store.GetPolicyVersion(ctx, c.caller.AccountID, arn, versionID)
	if err != nil {
		return policyError(err, arn, "", versionID)
	}
	return write(ctx, c, queryapi.PolicyVersionResult{PolicyVersion: wireVersion(v)})
}

func (m *Module) listPolicyVersions(ctx gas.Context, c *call) error {
	arn, err := policyARN(c)
	if err != nil {
		return err
	}
	marker, maxItems, err := queryapi.Page(c.params)
	if err != nil {
		return err
	}
	if err = m.authorize(ctx, c); err != nil {
		return err
	}

	page, err := m.store.ListPolicyVersions(ctx, contracts.ListPolicyVersionsInput{
		AccountID: c.caller.AccountID,
		PolicyARN: arn,
		Marker:    marker,
		MaxItems:  maxItems,
	})
	if err != nil {
		return policyError(err, arn, "", "")
	}
	versions := make([]queryapi.PolicyVersion, 0, len(page.Items))
	for i := range page.Items {
		versions = append(versions, wireVersion(&page.Items[i]))
	}
	return write(ctx, c, queryapi.ListPolicyVersionsResult{
		Versions:    queryapi.ListOf(versions),
		IsTruncated: page.Marker != "",
		Marker:      page.Marker,
	})
}

func (m *Module) deletePolicyVersion(ctx gas.Context, c *call) error {
	arn, versionID, err := versionParams(c)
	if err != nil {
		return err
	}
	if err = m.authorize(ctx, c); err != nil {
		return err
	}

	if err = m.store.DeletePolicyVersion(ctx, c.caller.AccountID, arn, versionID); err != nil {
		return policyError(err, arn, "", versionID)
	}
	return write(ctx, c, nil)
}

func (m *Module) setDefaultPolicyVersion(ctx gas.Context, c *call) error {
	arn, versionID, err := versionParams(c)
	if err != nil {
		return err
	}
	if err = m.authorize(ctx, c); err != nil {
		return err
	}

	if err = m.store.SetDefaultPolicyVersion(ctx, c.caller.AccountID, arn,
		versionID); err != nil {
		return policyError(err, arn, "", versionID)
	}
	return write(ctx, c, nil)
}
