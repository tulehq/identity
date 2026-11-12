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
