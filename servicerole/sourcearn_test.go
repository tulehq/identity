package servicerole_test

import (
	"strings"
	"testing"

	"tule.dev/identity/servicerole"
)

func TestIsSourceArn(t *testing.T) {
	for arn, want := range map[string]bool{
		"arn:aws:s3:::abc":    true, // the shortest bucket name S3 allows
		"arn:aws:s3:::photos": true,
		"arn:aws:lambda:us-east-1:000000000000:function:fn":              true,
		"arn:aws:sqs:us-east-1:000000000000:q":                           true,
		"arn:aws:s3:::" + strings.Repeat("a", 2048-len("arn:aws:s3:::")): true,
		"arn:aws:s3:::" + strings.Repeat("a", 2049-len("arn:aws:s3:::")): false,
		"arn:aws:s3:::":                     false,
		"arn:aws:lambda:us-east-1:12345:fn": false,
		"not an arn":                        false,
		"":                                  false,
	} {
		if got := servicerole.IsSourceArn(arn); got != want {
			t.Errorf("IsSourceArn(%.40q) = %v, want %v", arn, got, want)
		}
	}
}
