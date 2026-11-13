// Package rootcall makes the calls Tule services make to identity's
// internal endpoints: a POST of a JSON body, SigV4-signed with the root
// user's key for SigningName in SigningRegion.
package rootcall

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
)

// The SigV4 scope a call to an internal endpoint is signed for.
const (
	SigningName   = "identity"
	SigningRegion = "us-east-1"
)

// Caller signs and makes the calls. It is safe for concurrent use.
type Caller struct {
	http   *http.Client
	signer *v4.Signer
	creds  aws.Credentials
	base   string
}

// New returns a Caller of the identity at endpoint, an absolute http or
// https URL, signing with the root user's key. hc defaults to
// http.DefaultClient.
func New(endpoint, accessKeyID, secretAccessKey string, hc *http.Client) (*Caller, error) {
	u, err := url.Parse(endpoint)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil, fmt.Errorf("the endpoint %q is not an http or https URL", endpoint)
	}
	if accessKeyID == "" || secretAccessKey == "" {
		return nil, errors.New("the root user's access key ID and secret are required")
	}
	if hc == nil {
		hc = http.DefaultClient
	}
	return &Caller{
		http:   hc,
		signer: v4.NewSigner(),
		creds:  aws.Credentials{AccessKeyID: accessKeyID, SecretAccessKey: secretAccessKey},
		base:   strings.TrimSuffix(u.String(), "/"),
	}, nil
}

// Post posts body to path, signed, and returns the response's status and
// body. A body over limit bytes is an error that says so, rather than one
// cut short.
func (c *Caller) Post(
	ctx context.Context,
	path string,
	body []byte,
	limit int,
) (int, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.base+path, bytes.NewReader(body))
	if err != nil {
		return 0, nil, fmt.Errorf("build the request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	sum := sha256.Sum256(body)
	if err = c.signer.SignHTTP(ctx, c.creds, req, hex.EncodeToString(sum[:]),
		SigningName, SigningRegion, time.Now()); err != nil {
		return 0, nil, fmt.Errorf("sign the request: %w", err)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return 0, nil, fmt.Errorf("call %s: %w", path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, int64(limit)+1))
	if err != nil {
		return 0, nil, fmt.Errorf("read the response: %w", err)
	}
	if len(raw) > limit {
		return 0, nil, fmt.Errorf("the response exceeds %d bytes", limit)
	}
	return resp.StatusCode, raw, nil
}
