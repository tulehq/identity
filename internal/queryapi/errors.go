package queryapi

import (
	"bytes"
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"net/http"

	"github.com/gasmod/gas"

	"tule.dev/identity/internal/contracts"
	"tule.dev/identity/internal/httpx"
)

// Error is a Query protocol error document. It implements error so handlers
// and the validation helpers can return one directly.
type Error struct {
	Code    string
	Message string
	Status  int
}

func (e *Error) Error() string {
	return e.Code + ": " + e.Message
}

// NewError builds an error document with the given status and code.
func NewError(status int, code, message string) *Error {
	return &Error{Status: status, Code: code, Message: message}
}

// The error codes this service sends. The IAM ones are the awsQueryError
// codes of the IAM model's exception shapes, with the statuses the model
// gives them; the rest are the codes common to the Query services, with the
// statuses of the IAM and STS common errors references where those list
// them.
const (
	CodeNoSuchEntity        = "NoSuchEntity"
	CodeEntityAlreadyExists = "EntityAlreadyExists"
	CodeDeleteConflict      = "DeleteConflict"
	CodeLimitExceeded       = "LimitExceeded"
	CodeInvalidInput        = "InvalidInput"
	CodeServiceFailure      = "ServiceFailure"
	CodeMalformedPolicy     = "MalformedPolicyDocument"

	CodeAccessDenied          = "AccessDenied"
	CodeValidation            = "ValidationError"
	CodeInvalidParameterValue = "InvalidParameterValue"
	CodeInvalidAction         = "InvalidAction"
	CodeMissingAction         = "MissingAction"
	CodeMalformedQueryString  = "MalformedQueryString"
	CodeInternalFailure       = "InternalFailure"
	CodeMissingAuthToken      = "MissingAuthenticationToken"
	CodeIncompleteSignature   = "IncompleteSignature"
	CodeSignatureDoesNotMatch = "SignatureDoesNotMatch"
	CodeInvalidClientTokenID  = "InvalidClientTokenId"
	CodeExpiredToken          = "ExpiredToken"
)

// ErrValidation is a ValidationError, the error the Query services answer a
// parameter that breaks its model constraint with.
func ErrValidation(msg string) *Error {
	return NewError(http.StatusBadRequest, CodeValidation, msg)
}

// ErrInvalidInput is IAM's InvalidInput.
func ErrInvalidInput(msg string) *Error {
	return NewError(http.StatusBadRequest, CodeInvalidInput, msg)
}

// ErrInvalidParameterValue is the common InvalidParameterValue.
func ErrInvalidParameterValue(msg string) *Error {
	return NewError(http.StatusBadRequest, CodeInvalidParameterValue, msg)
}

// ErrAccessDenied is the AccessDenied a principal gets for an action it may
// not perform, in the form of AWS's messages: "User: <arn> is not authorized
// to perform: <action> on resource: <resource>". It is the answer to an
// AssumeRole whose role does not exist or does not trust the caller.
func ErrAccessDenied(callerARN, action, resource string) *Error {
	return NewError(http.StatusForbidden, CodeAccessDenied, fmt.Sprintf(
		"User: %s is not authorized to perform: %s on resource: %s",
		callerARN, action, resource))
}

// ErrNotAllowed is the AccessDenied of a request no identity-based policy
// allows, in the form of AWS's messages.
func ErrNotAllowed(callerARN, action, resource string) *Error {
	e := ErrAccessDenied(callerARN, action, resource)
	e.Message += " because no identity-based policy allows the " + action + " action"
	return e
}

// ErrExplicitlyDenied is the AccessDenied of a request an identity-based
// policy denies, in the form of AWS's messages.
func ErrExplicitlyDenied(callerARN, action, resource string) *Error {
	e := ErrAccessDenied(callerARN, action, resource)
	e.Message += " with an explicit deny in an identity-based policy"
	return e
}

// ErrMalformedPolicy is IAM's MalformedPolicyDocument.
func ErrMalformedPolicy(msg string) *Error {
	return NewError(http.StatusBadRequest, CodeMalformedPolicy, msg)
}

// ErrLimitExceeded is IAM's LimitExceeded.
func ErrLimitExceeded(msg string) *Error {
	return NewError(http.StatusConflict, CodeLimitExceeded, msg)
}

// ErrNoSuchEntity is IAM's NoSuchEntity.
func ErrNoSuchEntity(msg string) *Error {
	return NewError(http.StatusNotFound, CodeNoSuchEntity, msg)
}

// ErrEntityAlreadyExists is IAM's EntityAlreadyExists.
func ErrEntityAlreadyExists(msg string) *Error {
	return NewError(http.StatusConflict, CodeEntityAlreadyExists, msg)
}

// ErrNoSuchUser is the NoSuchEntity of a user name no user has.
func ErrNoSuchUser(name string) *Error {
	return NewError(http.StatusNotFound, CodeNoSuchEntity,
		"The user with name "+name+" cannot be found.")
}

// ErrNoSuchAccessKey is the NoSuchEntity of an access key ID that names no
// key of the IAM user, or of the account.
func ErrNoSuchAccessKey(id string) *Error {
	return NewError(http.StatusNotFound, CodeNoSuchEntity,
		"The Access Key with id "+id+" cannot be found.")
}

// ErrUserExists is the EntityAlreadyExists of a user name taken in the
// account.
func ErrUserExists(name string) *Error {
	return NewError(http.StatusConflict, CodeEntityAlreadyExists,
		"User with name "+name+" already exists.")
}

// ErrRootAccessKey is the error for an operation that would create, change
// or delete the root user's access key, which is configured rather than
// stored.
func ErrRootAccessKey() *Error {
	return ErrInvalidInput("The root user's access key is configured with " +
		"TULE_Auth_AccessKeyID and TULE_Auth_SecretAccessKey; this service cannot create, " +
		"change or delete it.")
}

// ErrInvalidAction is the error for an Action this service does not serve
// for the service and version the request names, whether or not AWS has it.
func ErrInvalidAction(op, version string) *Error {
	return NewError(http.StatusBadRequest, CodeInvalidAction,
		"Could not find operation "+op+" for version "+version)
}

// ErrMissingAction is the error for a request that names no Action.
func ErrMissingAction() *Error {
	return NewError(http.StatusBadRequest, CodeMissingAction,
		"A required parameter for the specified action isn't included in the request: Action.")
}

// ErrMalformedQueryString is the error for a body that does not parse as a
// form, with the status of the common errors reference.
func ErrMalformedQueryString() *Error {
	return NewError(http.StatusNotFound, CodeMalformedQueryString,
		"The query string contains a syntax error.")
}

// sentinelErrors maps the store's sentinels that need no request detail to
// the errors they become.
var sentinelErrors = []struct {
	err    error
	apiErr *Error
}{
	{contracts.ErrDeleteConflict, NewError(http.StatusConflict, CodeDeleteConflict,
		"Cannot delete entity, must delete access keys first.")},
	{contracts.ErrHasAttachedPolicies, NewError(http.StatusConflict, CodeDeleteConflict,
		"Cannot delete entity, must detach all policies first.")},
	{contracts.ErrHasInlinePolicies, NewError(http.StatusConflict, CodeDeleteConflict,
		"Cannot delete entity, must delete policies first.")},
	{contracts.ErrPolicyAttached, NewError(http.StatusConflict, CodeDeleteConflict,
		"Cannot delete a policy attached to entities.")},
	{contracts.ErrPolicyHasVersions, NewError(http.StatusConflict, CodeDeleteConflict,
		"This policy has more than one version. Before you delete a policy, you must "+
			"delete the policy's versions. The default version is deleted with the policy.")},
	{contracts.ErrDefaultPolicyVersion, NewError(http.StatusConflict, CodeDeleteConflict,
		"Cannot delete the default version of a policy.")},
	{contracts.ErrPolicyVersionLimitExceeded, NewError(http.StatusConflict, CodeLimitExceeded,
		fmt.Sprintf("A managed policy can have up to %d versions. Before you create a new "+
			"version, you must delete an existing version.", contracts.MaxPolicyVersions))},
	{contracts.ErrAWSManagedPolicy, ErrInvalidInput(
		"AWS managed policies can only be changed by AWS.")},
	{contracts.ErrAccessKeyLimitExceeded, NewError(http.StatusConflict, CodeLimitExceeded,
		fmt.Sprintf("Cannot exceed quota for AccessKeysPerUser: %d",
			contracts.MaxAccessKeysPerUser))},
	{contracts.ErrTagLimitExceeded, NewError(http.StatusConflict, CodeLimitExceeded,
		fmt.Sprintf("A user can carry at most %d tags.", contracts.MaxTagsPerUser))},
	{contracts.ErrInvalidMarker, ErrInvalidInput("Invalid Marker.")},
}

// ToError maps err to an error document of svc, logging it when it maps to
// an internal error. svc may be nil, for a failure before the request's
// service is known. It returns a copy, safe for the caller to fill in.
func ToError(ctx context.Context, svc *Service, err error) *Error {
	var apiErr *Error
	if errors.As(err, &apiErr) {
		cp := *apiErr
		return &cp
	}
	for _, se := range sentinelErrors {
		if errors.Is(err, se.err) {
			cp := *se.apiErr
			return &cp
		}
	}

	httpx.Logger(ctx).Error("request failed").Err("error", err).Send()
	code := CodeInternalFailure
	if svc != nil {
		code = svc.internalError
	}
	return NewError(http.StatusInternalServerError, code,
		"The request processing has failed because of an unknown error, exception or failure.")
}

// errorResponse is the error document of the Query protocol.
type errorResponse struct {
	XMLName   xml.Name    `xml:"ErrorResponse"`
	Namespace string      `xml:"xmlns,attr,omitempty"`
	Error     errorDetail `xml:"Error"`
	RequestID string      `xml:"RequestId"`
}

type errorDetail struct {
	Type    string `xml:"Type"`
	Code    string `xml:"Code"`
	Message string `xml:"Message"`
}

// WriteError renders err as an error response of svc.
func WriteError(ctx gas.Context, svc *Service, err error) error {
	WriteHTTPError(ctx.ResponseWriter(), ctx.Request(), svc, err)
	return nil
}

// WriteHTTPError is WriteError for plain http.Handler middleware, which has
// no gas.Context. svc may be nil, for a failure before the request's service
// is known; the document then carries no namespace.
func WriteHTTPError(w http.ResponseWriter, r *http.Request, svc *Service, err error) {
	apiErr := ToError(r.Context(), svc, err)

	doc := errorResponse{
		Error:     errorDetail{Type: "Sender", Code: apiErr.Code, Message: apiErr.Message},
		RequestID: httpx.RequestIDOf(r.Context()),
	}
	if apiErr.Status >= http.StatusInternalServerError {
		doc.Error.Type = "Receiver"
	}
	if svc != nil {
		doc.Namespace = svc.Namespace
	}

	var buf bytes.Buffer
	if mErr := xml.NewEncoder(&buf).Encode(doc); mErr != nil {
		httpx.Logger(r.Context()).Error("failed to encode error response").
			Err("error", mErr).Send()
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", ContentType)
	setRequestID(w, r)
	w.WriteHeader(apiErr.Status)
	if _, wErr := w.Write(buf.Bytes()); wErr != nil {
		httpx.Logger(r.Context()).Warn("failed to write error response").
			Err("error", wErr).Send()
	}
}
