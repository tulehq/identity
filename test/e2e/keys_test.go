//go:build e2e

package e2e

import (
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

// unknownKeyID is a well-formed access key ID no test creates.
const unknownKeyID = "AKIAZZZZZZZZZZZZZZZZ"

func TestCreateAccessKey(t *testing.T) {
	_, c := rootIAM(t)
	createUser(t, c, "dev")
	before := time.Now()

	out, err := c.CreateAccessKey(t.Context(), &iam.CreateAccessKeyInput{
		UserName: aws.String("dev"),
	})
	requireNoErr(t, err, "create access key")
	k := out.AccessKey
	if k == nil {
		t.Fatal("no access key returned")
	}

	requireMatch(t, accessKeyPattern, aws.ToString(k.AccessKeyId), "AccessKeyId")
	if aws.ToString(k.SecretAccessKey) == "" {
		t.Fatal("no SecretAccessKey")
	}
	// CreateAccessKey: "The default status for new keys is Active."
	requireEqual(t, k.Status, types.StatusTypeActive, "Status")
	requireEqual(t, aws.ToString(k.UserName), "dev", "UserName")
	requireRecent(t, k.CreateDate, before, time.Now(), "CreateDate")

	t.Run("ListAccessKeys agrees", func(t *testing.T) {
		got := listKeys(t, c, "dev")
		requireEqual(t, len(got), 1, "key count")
		requireEqual(t, aws.ToString(got[0].AccessKeyId), aws.ToString(k.AccessKeyId),
			"AccessKeyId")
		requireEqual(t, got[0].Status, types.StatusTypeActive, "Status")
		requireEqual(t, aws.ToString(got[0].UserName), "dev", "UserName")
		requireEqual(t, got[0].CreateDate.Unix(), k.CreateDate.Unix(), "CreateDate")
	})

	t.Run("second key is distinct", func(t *testing.T) {
		second := createKey(t, c, "dev")
		if second.AccessKeyID == aws.ToString(k.AccessKeyId) ||
			second.SecretAccessKey == aws.ToString(k.SecretAccessKey) {
			t.Fatal("second key repeats the first")
		}
		requireEqual(t, len(listKeys(t, c, "dev")), 2, "key count")
	})
}

func TestThirdAccessKeyIsRefused(t *testing.T) {
	// IAM quotas: two access keys per user, active or inactive (IAM User
	// Guide, IAM and STS quotas; "Manage access keys for IAM users").
	// LimitExceeded is in CreateAccessKey's errors.
	_, c := rootIAM(t)
	first := userWithKey(t, c, "dev")
	createKey(t, c, "dev")

	err := errOf(c.CreateAccessKey(t.Context(), &iam.CreateAccessKeyInput{
		UserName: aws.String("dev"),
	}))
	requireAs[*types.LimitExceededException](t, err)

	t.Run("an inactive key still counts", func(t *testing.T) {
		setKeyStatus(t, c, "dev", first.AccessKeyID, types.StatusTypeInactive)
		err := errOf(c.CreateAccessKey(t.Context(), &iam.CreateAccessKeyInput{
			UserName: aws.String("dev"),
		}))
		requireAs[*types.LimitExceededException](t, err)
	})

	requireEqual(t, len(listKeys(t, c, "dev")), 2, "key count")

	t.Run("another user is not limited", func(t *testing.T) {
		userWithKey(t, c, "other")
	})
}

func TestUpdateAccessKey(t *testing.T) {
	srv, c := rootIAM(t)
	key := userWithKey(t, c, "dev")

	setKeyStatus(t, c, "dev", key.AccessKeyID, types.StatusTypeInactive)
	got := listKeys(t, c, "dev")
	requireEqual(t, got[0].Status, types.StatusTypeInactive, "Status after deactivating")

	// UpdateAccessKey: Inactive "means that the key cannot be used".
	t.Run("inactive key is refused", func(t *testing.T) {
		requireCode(t, errOf(callerIdentity(t, srv, key)), codeInvalidClientToken)
	})

	setKeyStatus(t, c, "dev", key.AccessKeyID, types.StatusTypeActive)
	got = listKeys(t, c, "dev")
	requireEqual(t, got[0].Status, types.StatusTypeActive, "Status after reactivating")

	t.Run("reactivated key works", func(t *testing.T) {
		_, err := callerIdentity(t, srv, key)
		requireNoErr(t, err, "get caller identity with the reactivated key")
	})
}

func TestUpdateAccessKeyErrors(t *testing.T) {
	_, c := rootIAM(t)
	key := userWithKey(t, c, "dev")
	createUser(t, c, "other")

	t.Run("unknown key", func(t *testing.T) {
		err := errOf(c.UpdateAccessKey(t.Context(), &iam.UpdateAccessKeyInput{
			UserName:    aws.String("dev"),
			AccessKeyId: aws.String(unknownKeyID),
			Status:      types.StatusTypeInactive,
		}))
		requireAs[*types.NoSuchEntityException](t, err)
	})

	t.Run("unknown user", func(t *testing.T) {
		err := errOf(c.UpdateAccessKey(t.Context(), &iam.UpdateAccessKeyInput{
			UserName:    aws.String("nobody"),
			AccessKeyId: aws.String(key.AccessKeyID),
			Status:      types.StatusTypeInactive,
		}))
		requireAs[*types.NoSuchEntityException](t, err)
	})

	// Assumption: a key named with a user it does not belong to is not that
	// user's key, so NoSuchEntity; the reference does not spell this out.
	t.Run("another user's key", func(t *testing.T) {
		err := errOf(c.UpdateAccessKey(t.Context(), &iam.UpdateAccessKeyInput{
			UserName:    aws.String("other"),
			AccessKeyId: aws.String(key.AccessKeyID),
			Status:      types.StatusTypeInactive,
		}))
		requireAs[*types.NoSuchEntityException](t, err)
		requireEqual(t, listKeys(t, c, "dev")[0].Status, types.StatusTypeActive,
			"status of the key after the refused update")
	})

	// accessKeyIdType: at least 16 characters of [\w].
	t.Run("malformed key ID", func(t *testing.T) {
		err := errOf(c.UpdateAccessKey(t.Context(), &iam.UpdateAccessKeyInput{
			UserName:    aws.String("dev"),
			AccessKeyId: aws.String("short"),
			Status:      types.StatusTypeInactive,
		}))
		requireCode(t, err, codeValidation)
	})
}

func TestDeleteAccessKey(t *testing.T) {
	srv, c := rootIAM(t)
	key := userWithKey(t, c, "dev")
	kept := createKey(t, c, "dev")

	_, err := c.DeleteAccessKey(t.Context(), &iam.DeleteAccessKeyInput{
		UserName:    aws.String("dev"),
		AccessKeyId: aws.String(key.AccessKeyID),
	})
	requireNoErr(t, err, "delete access key")

	got := listKeys(t, c, "dev")
	requireEqual(t, len(got), 1, "key count")
	requireEqual(t, aws.ToString(got[0].AccessKeyId), kept.AccessKeyID, "remaining key")

	t.Run("deleted key is refused", func(t *testing.T) {
		requireCode(t, errOf(callerIdentity(t, srv, key)), codeInvalidClientToken)
	})

	t.Run("deleting it again", func(t *testing.T) {
		err := errOf(c.DeleteAccessKey(t.Context(), &iam.DeleteAccessKeyInput{
			UserName:    aws.String("dev"),
			AccessKeyId: aws.String(key.AccessKeyID),
		}))
		requireAs[*types.NoSuchEntityException](t, err)
	})

	t.Run("unknown user", func(t *testing.T) {
		err := errOf(c.DeleteAccessKey(t.Context(), &iam.DeleteAccessKeyInput{
			UserName:    aws.String("nobody"),
			AccessKeyId: aws.String(kept.AccessKeyID),
		}))
		requireAs[*types.NoSuchEntityException](t, err)
	})

	t.Run("the other key still works", func(t *testing.T) {
		_, err := callerIdentity(t, srv, kept)
		requireNoErr(t, err, "get caller identity with the remaining key")
	})
}

func TestListAccessKeysOfUserWithoutKeys(t *testing.T) {
	// ListAccessKeys: "If there is none, the operation returns an empty list."
	_, c := rootIAM(t)
	createUser(t, c, "keyless")
	out, err := c.ListAccessKeys(t.Context(), &iam.ListAccessKeysInput{
		UserName: aws.String("keyless"),
	})
	requireNoErr(t, err, "list access keys")
	requireEqual(t, len(out.AccessKeyMetadata), 0, "key count")
	requireEqual(t, out.IsTruncated, false, "IsTruncated")
}

func TestGetAccessKeyLastUsed(t *testing.T) {
	srv, c := rootIAM(t)
	key := userWithKey(t, c, "dev")

	// AccessKeyLastUsed: Region and ServiceName are "N/A" and LastUsedDate is
	// null for a key that has not been used.
	t.Run("never used", func(t *testing.T) {
		out := lastUsed(t, c, key.AccessKeyID)
		requireEqual(t, aws.ToString(out.UserName), "dev", "UserName")
		requireEqual(t, aws.ToString(out.AccessKeyLastUsed.Region), "N/A", "Region")
		requireEqual(t, aws.ToString(out.AccessKeyLastUsed.ServiceName), "N/A", "ServiceName")
		if out.AccessKeyLastUsed.LastUsedDate != nil {
			t.Fatalf("LastUsedDate %v for an unused key", *out.AccessKeyLastUsed.LastUsedDate)
		}
	})

	// Assumption: identity records a use of a key on its own STS endpoint, as
	// it does for the lookups the other services make through the signing-key
	// endpoint. ServiceName is the credential scope's service, "sts", and
	// Region its region.
	t.Run("after a use", func(t *testing.T) {
		before := time.Now()
		_, err := callerIdentity(t, srv, key)
		requireNoErr(t, err, "get caller identity")
		after := time.Now()

		out := lastUsed(t, c, key.AccessKeyID)
		requireEqual(t, aws.ToString(out.UserName), "dev", "UserName")
		requireEqual(t, aws.ToString(out.AccessKeyLastUsed.ServiceName), "sts", "ServiceName")
		requireEqual(t, aws.ToString(out.AccessKeyLastUsed.Region), signingRegion, "Region")
		requireRecent(t, out.AccessKeyLastUsed.LastUsedDate, before, after, "LastUsedDate")
	})
}

func TestUserKeySignsRequests(t *testing.T) {
	srv, c := rootIAM(t)
	key := userWithKey(t, c, "signer")
	user, err := c.GetUser(t.Context(), &iam.GetUserInput{UserName: aws.String("signer")})
	requireNoErr(t, err, "get user")

	// GetCallerIdentity returns the user's ARN, its unique ID as UserId (the
	// aws:userid of an IAM user, IAM User Guide, policy variables), and the
	// account.
	out, err := callerIdentity(t, srv, key)
	requireNoErr(t, err, "get caller identity")
	requireEqual(t, aws.ToString(out.Arn), aws.ToString(user.User.Arn), "Arn")
	requireEqual(t, aws.ToString(out.UserId), aws.ToString(user.User.UserId), "UserId")
	requireEqual(t, aws.ToString(out.Account), defaultAccountID, "Account")
}

func TestUserKeyIsDeniedIAM(t *testing.T) {
	// The spec: until policies exist only admin principals may call IAM; any
	// other principal gets AccessDenied.
	srv, c := rootIAM(t)
	key := userWithKey(t, c, "plain")
	uc := iamFor(srv, key)

	t.Run("ListUsers", func(t *testing.T) {
		requireCode(t, errOf(uc.ListUsers(t.Context(), &iam.ListUsersInput{})), codeAccessDenied)
	})
	t.Run("CreateUser", func(t *testing.T) {
		err := errOf(uc.CreateUser(t.Context(), &iam.CreateUserInput{
			UserName: aws.String("sneaky"),
		}))
		requireCode(t, err, codeAccessDenied)
	})
	t.Run("CreateAccessKey for itself", func(t *testing.T) {
		err := errOf(uc.CreateAccessKey(t.Context(), &iam.CreateAccessKeyInput{
			UserName: aws.String("plain"),
		}))
		requireCode(t, err, codeAccessDenied)
	})
	t.Run("DeleteUser", func(t *testing.T) {
		err := errOf(uc.DeleteUser(t.Context(), &iam.DeleteUserInput{
			UserName: aws.String("plain"),
		}))
		requireCode(t, err, codeAccessDenied)
	})

	// Nothing changed.
	requireAs[*types.NoSuchEntityException](t, errOf(c.GetUser(t.Context(),
		&iam.GetUserInput{UserName: aws.String("sneaky")})))
	requireEqual(t, len(listKeys(t, c, "plain")), 1, "key count")

	// Every active principal may still call STS.
	t.Run("GetAccessKeyInfo is allowed", func(t *testing.T) {
		out, err := stsFor(srv, key).GetAccessKeyInfo(t.Context(), &sts.GetAccessKeyInfoInput{
			AccessKeyId: aws.String(key.AccessKeyID),
		})
		requireNoErr(t, err, "get access key info")
		requireEqual(t, aws.ToString(out.Account), defaultAccountID, "Account")
	})
}

func listKeys(t *testing.T, c *iam.Client, user string) []types.AccessKeyMetadata {
	t.Helper()
	out, err := c.ListAccessKeys(t.Context(), &iam.ListAccessKeysInput{
		UserName: aws.String(user),
	})
	requireNoErr(t, err, "list access keys of "+user)
	return out.AccessKeyMetadata
}

func setKeyStatus(t *testing.T, c *iam.Client, user, keyID string, status types.StatusType) {
	t.Helper()
	_, err := c.UpdateAccessKey(t.Context(), &iam.UpdateAccessKeyInput{
		UserName:    aws.String(user),
		AccessKeyId: aws.String(keyID),
		Status:      status,
	})
	requireNoErr(t, err, "set key status to "+string(status))
}

func lastUsed(t *testing.T, c *iam.Client, keyID string) *iam.GetAccessKeyLastUsedOutput {
	t.Helper()
	out, err := c.GetAccessKeyLastUsed(t.Context(), &iam.GetAccessKeyLastUsedInput{
		AccessKeyId: aws.String(keyID),
	})
	requireNoErr(t, err, "get access key last used")
	if out.AccessKeyLastUsed == nil {
		t.Fatal("no AccessKeyLastUsed")
	}
	return out
}
