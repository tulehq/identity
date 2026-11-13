// Package principals binds the principals of a resource-based policy to
// unique IDs, as AWS does when the policy is saved, and shows a bound
// policy as AWS shows it, through identity's principal-ID endpoint.
//
// AWS turns a user or role ARN in a policy's Principal into the
// principal's unique ID when the policy is saved, so a user or role deleted
// and created again under the same ARN is another principal, which the
// policy does not name: "the new role has a new principal ID that does not
// match the ID stored in the trust policy. When this happens, the principal
// ID appears in resource-based policies because AWS can no longer map it
// back to a valid ARN" (the IAM User Guide, AWS JSON policy elements:
// Principal). A service that stores resource-based policies calls Bind on
// save, evaluates the bound document, which tule.dev/policy matches by
// unique ID, and calls Show to return it.
//
// The endpoint is not an AWS API. Like the signing-key endpoint, it is a
// SigV4-signed POST, with the root user's key for the signing name
// identity, of a JSON Request to Path. It resolves user and role ARNs to
// the unique IDs of the users and roles that have them now, and unique IDs
// to the current ARNs of the users and roles that have them, at most
// MaxBatch of both in one call; Bind and Show split larger sets.
package principals

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strings"

	"tule.dev/identity/internal/contracts"
	"tule.dev/identity/internal/rootcall"
	"tule.dev/identity/internal/trustdoc"
)

// Path is where identity serves the principal-ID endpoint, beside the
// signing-key endpoint under /_internal/.
const Path = "/_internal/principal-ids"

// MaxBatch is the most ARNs and IDs, together, one call may name.
const MaxBatch = 1000

// Request is the body of a call: user and role ARNs to resolve to unique
// IDs, and user and role unique IDs to resolve to ARNs. Each ARN is a user's
// or a role's, arn:aws:iam::<account>:user/<path><name> or
// arn:aws:iam::<account>:role/<path><name>, and each ID a user's (AIDA...)
// or a role's (AROA...); see IsUniqueID.
type Request struct {
	ARNs []string `json:"Arns,omitempty"`
	IDs  []string `json:"Ids,omitempty"`
}

// Response is the body of a successful call. IDs maps each requested ARN
// that a user or role has now, its path and name compared with their case,
// to that user's or role's unique ID; ARNs maps each requested ID that a
// user or role has to its current ARN. An ARN or ID no user or role has is
// left out.
type Response struct {
	IDs  map[string]string `json:"Ids"`
	ARNs map[string]string `json:"Arns"`
}

// ErrorResponse is the body of a failed call.
type ErrorResponse struct {
	Code    string `json:"Code"`
	Message string `json:"Message"`
}

// CodeInvalidRequest is the code of a 400 answer: the body is not a
// request, names more than MaxBatch values, or names a value that is not a
// user or role ARN, or not a unique ID. The endpoint's own authentication
// failures are 403 with the sigv4 Kind as the code, and a failure of
// identity is 500 InternalFailure.
const CodeInvalidRequest = "InvalidRequest"

// ErrInvalidPrincipal is what an *InvalidPrincipalError matches with
// errors.Is.
var ErrInvalidPrincipal = errors.New("principals: invalid principal in policy")

// InvalidPrincipalError is Bind's answer to a policy that names a user or
// role ARN no user or role has. AWS refuses such a policy; S3, for one,
// with MalformedPolicy, "Invalid principal in policy". The service answers
// with its own API's error.
type InvalidPrincipalError struct {
	// ARN is the first such ARN, in the order the policy names them.
	ARN string
}

func (e *InvalidPrincipalError) Error() string {
	return "principals: no user or role has the ARN " + e.ARN
}

// Is reports whether target is ErrInvalidPrincipal.
func (e *InvalidPrincipalError) Is(target error) bool {
	return target == ErrInvalidPrincipal
}

// Error is a failed call: the endpoint refused the caller or the request,
// or failed.
type Error struct {
	Code    string
	Message string
	Status  int
}

func (e *Error) Error() string {
	return fmt.Sprintf("principals: the principal-ID endpoint answered %d %s: %s",
		e.Status, e.Code, e.Message)
}

// uniqueID is the form of a user's or a role's unique ID: AIDA or AROA and
// upper-case letters and digits, 16 to 128 characters in all, the IAM API's
// bounds on UserId and RoleId (idType). tule.dev/policy accepts the same
// form in a Principal.
var uniqueID = regexp.MustCompile(`^(?:AIDA|AROA)[A-Z0-9]{12,124}$`)

// IsUniqueID reports whether s has the form of a user's or a role's unique
// ID.
func IsUniqueID(s string) bool {
	return uniqueID.MatchString(s)
}

// IsBindable reports whether s is a principal AWS binds to a unique ID: a
// user's or a role's ARN. Account IDs, root ARNs, assumed-role and
// federated-user session ARNs, "*" and unique IDs are not bound.
func IsBindable(s string) bool {
	return contracts.IsBindable(s)
}

// Config configures a Client.
type Config struct {
	// HTTPClient makes the calls. It defaults to http.DefaultClient.
	HTTPClient *http.Client
	// Endpoint is identity's base URL, such as http://localhost:9030.
	Endpoint string
	// AccessKeyID and SecretAccessKey are the root user's key, which the
	// calls are signed with.
	AccessKeyID     string
	SecretAccessKey string
}

// Client calls the principal-ID endpoint. It caches nothing, so every Bind
// and Show sees the users and roles as they are. It is safe for concurrent
// use.
type Client struct {
	caller *rootcall.Caller
}

// New returns a Client for cfg. It fails when the endpoint is not an
// absolute http or https URL, or the key is not set.
func New(cfg Config) (*Client, error) {
	c, err := rootcall.New(cfg.Endpoint, cfg.AccessKeyID, cfg.SecretAccessKey, cfg.HTTPClient)
	if err != nil {
		return nil, fmt.Errorf("principals: %w", err)
	}
	return &Client{caller: c}, nil
}

// Bind returns doc, a resource-based policy that parsed, with each user and
// role ARN in the AWS values of its Principal and NotPrincipal elements
// replaced by the unique ID of the IAM user or role that has it now. Account
// IDs, root ARNs, session ARNs, "*", unique IDs, service and other
// principals, and ARNs in conditions, such as aws:PrincipalArn, are kept,
// as AWS keeps them. The document is otherwise kept as it was written, its
// members in their order; where an ID replaces an ARN, the white space of
// the object it is in is not kept. A document that names no user or role
// ARN is returned unchanged.
//
// An ARN no user or role has is an *InvalidPrincipalError, which matches
// ErrInvalidPrincipal. Any other failure is an *Error or a transport error.
func (c *Client) Bind(ctx context.Context, doc string) (string, error) {
	arns, err := collect(doc, IsBindable)
	if err != nil {
		return "", err
	}
	ids, _, err := c.resolve(ctx, arns, nil)
	if err != nil {
		return "", err
	}
	for _, arn := range arns {
		if _, ok := ids[arn]; !ok {
			return "", &InvalidPrincipalError{ARN: arn}
		}
	}
	return rewrite(doc, ids)
}

// Show returns doc, a policy Bind returned, as AWS shows it: each unique ID
// in the AWS values of its Principal and NotPrincipal elements that a user
// or role still has becomes that user's or role's current ARN, and one that
// no user or role has stays the ID, as AWS shows it once it "can no longer
// map it back to a valid ARN". A document that names no unique ID is
// returned unchanged. A failure is an *Error or a transport error.
func (c *Client) Show(ctx context.Context, doc string) (string, error) {
	ids, err := collect(doc, IsUniqueID)
	if err != nil {
		return "", err
	}
	_, arns, err := c.resolve(ctx, nil, ids)
	if err != nil {
		return "", err
	}
	return rewrite(doc, arns)
}

// collect returns the distinct AWS principal values of doc that keep
// selects, in the order doc names them.
func collect(doc string, keep func(string) bool) ([]string, error) {
	var out []string
	seen := map[string]bool{}
	_, _, err := trustdoc.RewritePrincipals(doc, func(v string) string {
		if keep(v) && !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
		return v
	})
	if err != nil {
		return nil, fmt.Errorf("principals: %w", err)
	}
	return out, nil
}

// rewrite returns doc with each AWS principal value that to maps replaced
// by what it maps to.
func rewrite(doc string, to map[string]string) (string, error) {
	if len(to) == 0 {
		return doc, nil
	}
	out, _, err := trustdoc.RewritePrincipals(doc, func(v string) string {
		if r, ok := to[v]; ok {
			return r
		}
		return v
	})
	if err != nil {
		return "", fmt.Errorf("principals: %w", err)
	}
	return out, nil
}

// maxResponseSize bounds what is read of a response: MaxBatch pairs of an
// ARN and an ID. A user or role ARN is at most 2,048 characters
// (arnType), an ID 128, and each character is written in at most six bytes
// as JSON; 16 MiB covers that with room to spare.
const maxResponseSize = 16 << 20

// resolve resolves the ARNs and the IDs, MaxBatch at a time.
func (c *Client) resolve(
	ctx context.Context,
	arns, ids []string,
) (map[string]string, map[string]string, error) {
	gotIDs, gotARNs := map[string]string{}, map[string]string{}
	for len(arns) > 0 || len(ids) > 0 {
		var req Request
		n := min(len(arns), MaxBatch)
		req.ARNs, arns = arns[:n], arns[n:]
		n = min(len(ids), MaxBatch-len(req.ARNs))
		req.IDs, ids = ids[:n], ids[n:]
		out, err := c.call(ctx, req)
		if err != nil {
			return nil, nil, err
		}
		for k, v := range out.IDs {
			gotIDs[k] = v
		}
		for k, v := range out.ARNs {
			gotARNs[k] = v
		}
	}
	return gotIDs, gotARNs, nil
}

func (c *Client) call(ctx context.Context, req Request) (*Response, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("principals: encode the request: %w", err)
	}
	status, raw, err := c.caller.Post(ctx, Path, body, maxResponseSize)
	if err != nil {
		return nil, fmt.Errorf("principals: %w", err)
	}
	if status != http.StatusOK {
		var e ErrorResponse
		if json.Unmarshal(raw, &e) != nil {
			return nil, &Error{Status: status, Message: string(raw)}
		}
		return nil, &Error{Status: status, Code: e.Code, Message: e.Message}
	}
	var out Response
	if err = json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("principals: decode the response: %w", err)
	}
	if err = checkResponse(&req, &out); err != nil {
		return nil, &Error{Status: status, Code: CodeInvalidResponse, Message: err.Error()}
	}
	return &out, nil
}

// CodeInvalidResponse is the Code of the *Error for an answer that breaks
// the endpoint's contract: one that resolves a value the request did not
// name, an ARN to something that is not a unique ID, an ID to something
// that is not a user or role ARN, or a user to a role's ID (AROA) or a role
// to a user's (AIDA).
const CodeInvalidResponse = "InvalidResponse"

// idPrefix is the prefix of the unique ID of the IAM user or role arn
// names: AIDA for a user and AROA for a role (the IAM User Guide, IAM
// identifiers, unique ID prefixes).
func idPrefix(arn string) string {
	if _, _, _, ok := contracts.ParseUserARN(arn); ok {
		return "AIDA"
	}
	return "AROA"
}

func checkResponse(req *Request, out *Response) error {
	if err := checkResolved(req.ARNs, out.IDs, false); err != nil {
		return err
	}
	return checkResolved(req.IDs, out.ARNs, true)
}

// checkResolved checks that got resolves only values asked names, each an
// ARN to a unique ID of its kind, or, when byID, a unique ID to an ARN of
// its kind.
func checkResolved(asked []string, got map[string]string, byID bool) error {
	named := make(map[string]bool, len(asked))
	for _, v := range asked {
		named[v] = true
	}
	for from, to := range got {
		arn, id := from, to
		if byID {
			arn, id = to, from
		}
		if !named[from] || !IsBindable(arn) || !IsUniqueID(id) ||
			!strings.HasPrefix(id, idPrefix(arn)) {
			return fmt.Errorf("the endpoint resolved %q to %q", from, to)
		}
	}
	return nil
}
