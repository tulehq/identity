package sqlimpl

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
)

// The ID formats IAM and STS use: a four-letter prefix naming what the ID is
// (the IAM User Guide's table of unique ID prefixes), then characters of the
// base32 alphabet, to the lengths of the references' examples: 20 characters
// for an access key ID (AKIAIOSFODNN7EXAMPLE) and 21 for a user or role ID
// (AIDAJQABLZS4A3QDU576Q), as are role and managed policy IDs. A secret is 40 characters of the base64 alphabet,
// as the example wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY is.
const (
	base32Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
	base64Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

	userIDPrefix     = "AIDA"
	accessKeyPrefix  = "AKIA"
	sessionKeyPrefix = "ASIA"
	roleIDPrefix     = "AROA"
	policyIDPrefix   = "ANPA"

	accessKeySuffixLength = 16
	uniqueIDSuffixLength  = 17
	secretLength          = 40

	// sessionTokenBytes is how much randomness a session token carries. AWS
	// documents its tokens as opaque and of no fixed size; this one is
	// base64, 88 characters.
	sessionTokenBytes = 64
)

func newUserID() (string, error) {
	return prefixed(userIDPrefix, uniqueIDSuffixLength)
}

func newAccessKeyID() (string, error) {
	return prefixed(accessKeyPrefix, accessKeySuffixLength)
}

func newSessionKeyID() (string, error) {
	return prefixed(sessionKeyPrefix, accessKeySuffixLength)
}

func newSecret() (string, error) {
	return randomString(base64Alphabet, secretLength)
}

func newSessionToken() (string, error) {
	b := make([]byte, sessionTokenBytes)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("failed to generate a session token: %w", err)
	}
	return base64.StdEncoding.EncodeToString(b), nil
}

func newRoleID() (string, error) {
	return prefixed(roleIDPrefix, uniqueIDSuffixLength)
}

func newPolicyID() (string, error) {
	return prefixed(policyIDPrefix, uniqueIDSuffixLength)
}

// prefixed is prefix followed by n characters of the base32 alphabet.
func prefixed(prefix string, n int) (string, error) {
	s, err := randomString(base32Alphabet, n)
	if err != nil {
		return "", err
	}
	return prefix + s, nil
}

// randomString returns n characters drawn uniformly from alphabet, which must
// be at most 256 characters long.
func randomString(alphabet string, n int) (string, error) {
	// Bytes at or above limit are discarded, so every character is equally
	// likely rather than the first 256 % len(alphabet) being favored.
	limit := 256 - 256%len(alphabet)
	out := make([]byte, 0, n)
	buf := make([]byte, n)
	for len(out) < n {
		if _, err := rand.Read(buf); err != nil {
			return "", fmt.Errorf("failed to generate an ID: %w", err)
		}
		for _, b := range buf {
			if int(b) < limit && len(out) < n {
				out = append(out, alphabet[int(b)%len(alphabet)])
			}
		}
	}
	return string(out), nil
}
