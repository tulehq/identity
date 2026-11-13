// Package sdkimpl implements contracts.AccountDirectory by asking the
// accounts service, Tule's Organizations, through the AWS SDK's
// Organizations client, signed with the root user's key.
package sdkimpl

import (
	"context"
	"errors"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/organizations"
	"github.com/aws/aws-sdk-go-v2/service/organizations/types"

	"tule.dev/identity/internal/contracts"
)

// signingRegion is the region the client signs for. Organizations is global,
// and its AWS endpoint signs for us-east-1.
const signingRegion = "us-east-1"

// Settings are where the accounts service is and the key to sign with.
type Settings struct {
	// Endpoint is the accounts service's base URL. Empty means there is no
	// accounts service, and every account is unknown.
	Endpoint        string
	AccessKeyID     string
	SecretAccessKey string
}

// Directory asks the accounts service about the organization and its
// accounts. It is safe for
// concurrent use.
type Directory struct {
	client *organizations.Client
}

var _ contracts.AccountDirectory = (*Directory)(nil)

// New returns a Directory for settings.
func New(settings Settings) *Directory {
	if settings.Endpoint == "" {
		return &Directory{}
	}
	return &Directory{client: organizations.New(organizations.Options{
		Region:       signingRegion,
		BaseEndpoint: aws.String(settings.Endpoint),
		Credentials: credentials.NewStaticCredentialsProvider(
			settings.AccessKeyID, settings.SecretAccessKey, ""),
	})}
}

// IsActiveMember describes the account to the accounts service. An account
// it does not know, or an organization that does not exist, is
// contracts.ErrAccountNotFound, and with no accounts service configured every
// call is contracts.ErrNoAccountDirectory.
func (d *Directory) IsActiveMember(ctx context.Context, accountID string) (bool, error) {
	if d.client == nil {
		return false, contracts.ErrNoAccountDirectory
	}
	out, err := d.client.DescribeAccount(ctx, &organizations.DescribeAccountInput{
		AccountId: aws.String(accountID),
	})
	var (
		notFound *types.AccountNotFoundException
		notInUse *types.AWSOrganizationsNotInUseException
	)
	switch {
	case errors.As(err, &notFound), errors.As(err, &notInUse):
		return false, contracts.ErrAccountNotFound
	case err != nil:
		return false, fmt.Errorf("describe account %s: %w", accountID, err)
	}
	return out.Account != nil && out.Account.State == types.AccountStateActive, nil
}

// ManagementAccountID describes the organization to the accounts service and
// returns its management account. An organization that does not exist is
// contracts.ErrAccountNotFound, and with no accounts service configured every
// call is contracts.ErrNoAccountDirectory.
func (d *Directory) ManagementAccountID(ctx context.Context) (string, error) {
	if d.client == nil {
		return "", contracts.ErrNoAccountDirectory
	}
	out, err := d.client.DescribeOrganization(ctx, &organizations.DescribeOrganizationInput{})
	var notInUse *types.AWSOrganizationsNotInUseException
	switch {
	case errors.As(err, &notInUse):
		return "", contracts.ErrAccountNotFound
	case err != nil:
		return "", fmt.Errorf("describe organization: %w", err)
	case out.Organization == nil || out.Organization.MasterAccountId == nil:
		return "", errors.New("describe organization: the response names no management account")
	}
	return *out.Organization.MasterAccountId, nil
}

// maxDepth bounds the parents OrganizationOf walks up from an account: the
// root and the OUs under it, which accounts nests at most five levels deep,
// with room to spare. A deeper walk is an error, not an endless loop.
const maxDepth = 10

// OrganizationOf describes the organization and the account to the accounts
// service, and walks the account's parents up to the root with ListParents.
// An account that is not a member (AccountNotFoundException), or not
// ACTIVE, and an organization that does not exist, are the zero
// Organization; with no accounts service configured every call is
// contracts.ErrNoAccountDirectory.
func (d *Directory) OrganizationOf(
	ctx context.Context,
	accountID string,
) (contracts.Organization, error) {
	var none contracts.Organization
	if d.client == nil {
		return none, contracts.ErrNoAccountDirectory
	}
	id, err := d.organizationID(ctx)
	if err != nil || id == "" {
		return none, err
	}
	active, err := d.IsActiveMember(ctx, accountID)
	switch {
	case errors.Is(err, contracts.ErrAccountNotFound):
		return none, nil
	case err != nil:
		return none, err
	case !active:
		return none, nil
	}
	ids, err := d.parents(ctx, accountID)
	if err != nil {
		return none, err
	}
	path := id + "/"
	for i := len(ids) - 1; i >= 0; i-- {
		path += ids[i] + "/"
	}
	return contracts.Organization{ID: id, Path: path}, nil
}

// organizationID describes the organization and returns its ID, or ""
// when there is none.
func (d *Directory) organizationID(ctx context.Context) (string, error) {
	org, err := d.client.DescribeOrganization(ctx, &organizations.DescribeOrganizationInput{})
	var notInUse *types.AWSOrganizationsNotInUseException
	switch {
	case errors.As(err, &notInUse):
		return "", nil
	case err != nil:
		return "", fmt.Errorf("describe organization: %w", err)
	case org.Organization == nil || aws.ToString(org.Organization.Id) == "":
		return "", errors.New("describe organization: the response names no organization ID")
	}
	return aws.ToString(org.Organization.Id), nil
}

// parents returns the IDs of the account's parents, its own parent first and
// the root last.
func (d *Directory) parents(ctx context.Context, accountID string) ([]string, error) {
	var ids []string
	child := accountID
	for range maxDepth {
		out, err := d.client.ListParents(ctx, &organizations.ListParentsInput{
			ChildId: aws.String(child),
		})
		if err != nil {
			return nil, fmt.Errorf("list the parents of %s: %w", child, err)
		}
		// "In the current release, a child can have only a single parent"
		// (the Organizations API Reference, ListParents).
		if len(out.Parents) != 1 || aws.ToString(out.Parents[0].Id) == "" {
			return nil, fmt.Errorf("list the parents of %s: %d parents, want one",
				child, len(out.Parents))
		}
		p := out.Parents[0]
		ids = append(ids, aws.ToString(p.Id))
		if p.Type == types.ParentTypeRoot {
			return ids, nil
		}
		child = aws.ToString(p.Id)
	}
	return nil, fmt.Errorf("the parents of %s are more than %d deep", accountID, maxDepth)
}
