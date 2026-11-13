package app

import (
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
)

func TestAServiceTrustPolicyIsStoredAndReturnedAsSent(t *testing.T) {
	ctx := t.Context()
	url := startApp(t, t.TempDir(), nil)
	root := iamClient(url, rootCreds())
	lambdaTrust := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow",` +
		`"Principal":{"Service":"lambda.amazonaws.com"},"Action":"sts:AssumeRole"}]}`

	_, err := root.CreateRole(ctx, &iam.CreateRoleInput{
		RoleName: aws.String("fn"), AssumeRolePolicyDocument: aws.String(lambdaTrust),
	})
	check(t, err == nil, "create the role: %v", err)
	check(t, shownTrustOf(t, root, "fn") == lambdaTrust, "trust policy = %s",
		shownTrustOf(t, root, "fn"))

	// A trust policy naming a user and a service: once the user is gone its
	// ARN shows as its unique ID, and the service is left as it was.
	alice := createUserWithKey(t, root, "alice")
	mixed := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":` +
		`{"AWS":"arn:aws:iam::000000000000:user/alice","Service":["lambda.amazonaws.com",` +
		`"states.amazonaws.com"]},"Action":"sts:AssumeRole"}]}`
	_, err = root.UpdateAssumeRolePolicy(ctx, &iam.UpdateAssumeRolePolicyInput{
		RoleName: aws.String("fn"), PolicyDocument: aws.String(mixed),
	})
	check(t, err == nil, "update the trust policy: %v", err)
	check(t, shownTrustOf(t, root, "fn") == mixed, "trust policy = %s", shownTrustOf(t, root, "fn"))

	me, err := root.GetUser(ctx, &iam.GetUserInput{UserName: aws.String("alice")})
	check(t, err == nil, "get alice: %v", err)
	deleteUser(t, root, "alice", alice.AccessKeyID)
	shown := shownTrustOf(t, root, "fn")
	check(t, strings.Contains(shown, `"AWS":"`+aws.ToString(me.User.UserId)+`"`) &&
		strings.Contains(shown, `"Service":["lambda.amazonaws.com","states.amazonaws.com"]`),
		"trust policy after the user is deleted = %s", shown)
}
