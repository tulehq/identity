package app

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	"github.com/gasmod/gas"
	"tule.dev/sigv4"

	"tule.dev/identity/internal/contracts"
	"tule.dev/identity/internal/modules/health"
	"tule.dev/identity/internal/modules/signingkey"
	"tule.dev/identity/internal/queryapi"
	"tule.dev/identity/keysource"
)

// verifySignature returns the middleware that rejects requests whose SigV4
// signature does not verify.
//
// The IAM and STS API is verified against the store, which knows the root
// user's key, the users' keys and the role sessions'; each verified request
// records its key's use, for GetAccessKeyLastUsed. The signing-key endpoint
// is verified against the root user's key alone, signed for
// keysource.SigningName, before it reads its body.
//
// The health probes are exempt, so a container's health check needs no
// credentials; nothing else is, because any web page the developer has open
// can reach a server on localhost, and this one issues credentials.
func verifySignature(auth *authSettings) (func(http.Handler) http.Handler, error) {
	api, err := sigv4.New(requestStore{}, sigv4.WithErrorMap(queryError))
	if err != nil {
		return nil, fmt.Errorf("failed to create the API verifier: %w", err)
	}
	root, err := sigv4.NewStaticKey(sigv4.StaticKeyConfig{
		AccessKeyID:     auth.AccessKeyID,
		SecretAccessKey: auth.SecretAccessKey,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create the root user's key source: %w", err)
	}
	internal, err := sigv4.New(root, sigv4.WithService(keysource.SigningName))
	if err != nil {
		return nil, fmt.Errorf("failed to create the signing-key endpoint verifier: %w", err)
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch {
			case isProbe(r.URL.Path):
				next.ServeHTTP(w, r)
			case r.URL.Path == keysource.Path:
				verified, vErr := internal.Verify(r)
				if vErr != nil {
					signingkey.WriteHTTPError(w, r, vErr)
					return
				}
				next.ServeHTTP(w, verified)
			default:
				serveAPI(w, r, api, next)
			}
		})
	}, nil
}

// serveAPI verifies an API request against the store and serves it. A
// failure before the scope is verified is answered without a service:
// nothing about the request is trusted yet.
func serveAPI(w http.ResponseWriter, r *http.Request, api *sigv4.Verifier, next http.Handler) {
	store, err := gas.ResolveFromRequestScope[contracts.IdentityProvider](r)
	if err != nil {
		queryapi.WriteHTTPError(w, r, nil, fmt.Errorf("resolve the identity store: %w", err))
		return
	}

	verified, err := api.Verify(r.WithContext(withStore(r.Context(), store)))
	if err != nil {
		queryapi.WriteHTTPError(w, r, nil, err)
		return
	}
	serveVerified(w, verified, store, next)
}

// serveVerified records the use of the key the verified request r was
// signed with, and serves r with the service of its verified credential
// scope on its context, for the dispatcher to route on. A request scoped to
// neither IAM nor STS is not recorded: it is answered as an invalid action.
func serveVerified(
	w http.ResponseWriter,
	r *http.Request,
	store contracts.IdentityProvider,
	next http.Handler,
) {
	scope, ok := sigv4.ScopeFrom(r.Context())
	if !ok {
		queryapi.WriteHTTPError(w, r, nil,
			errors.New("the verified request carries no credential scope"))
		return
	}
	svc := queryapi.ServiceNamed(scope.Service)
	if svc != nil {
		if err := store.RecordKeyUse(r.Context(), scope.AccessKeyID, svc.Name,
			scope.Region); err != nil {
			queryapi.WriteHTTPError(w, r, svc, fmt.Errorf("record the key's use: %w", err))
			return
		}
	}
	next.ServeHTTP(w, r.WithContext(queryapi.WithService(r.Context(), svc)))
}

func isProbe(path string) bool {
	return path == health.HealthPath || path == health.ReadyPath
}

type storeKey struct{}

func withStore(ctx context.Context, store contracts.IdentityProvider) context.Context {
	return context.WithValue(ctx, storeKey{}, store)
}

// requestStore is the sigv4.KeySource of the API: the store, which the
// middleware resolves from the request's scope and puts on the context the
// verifier passes through, since the verifier is built when the middleware
// is installed and the store only by the container after.
type requestStore struct{}

func (requestStore) SigningKey(ctx context.Context, scope sigv4.Scope) (sigv4.Key, error) {
	store, ok := ctx.Value(storeKey{}).(contracts.IdentityProvider)
	if !ok {
		return sigv4.Key{}, errors.New("the request context carries no identity store")
	}
	//nolint:wrapcheck // the store's errors are the sentinels the verifier reads
	return store.SigningKey(ctx, scope)
}

// queryError maps a verification failure to the error AWS's Query services
// answer it with. An unknown or inactive key, and a session token that is
// not the key's, are InvalidClientTokenId; an expired token is ExpiredToken;
// a wrong signature, or a request dated too far from the clock, is
// SignatureDoesNotMatch; a malformed signature is IncompleteSignature, with
// the status of the common errors reference.
func queryError(e *sigv4.Error) error {
	status, code, msg := http.StatusBadRequest, queryapi.CodeIncompleteSignature, e.Message
	switch e.Kind {
	case sigv4.KindMissingAuth:
		status, code = http.StatusForbidden, queryapi.CodeMissingAuthToken
		msg = "Request is missing Authentication Token"
	case sigv4.KindUnknownAccessKey, sigv4.KindInvalidSessionToken:
		status, code = http.StatusForbidden, queryapi.CodeInvalidClientTokenID
		msg = "The security token included in the request is invalid."
	case sigv4.KindExpiredSessionToken:
		status, code = http.StatusForbidden, queryapi.CodeExpiredToken
		msg = "The security token included in the request is expired"
	case sigv4.KindSignatureMismatch, sigv4.KindRequestTimeTooSkewed:
		status, code = http.StatusForbidden, queryapi.CodeSignatureDoesNotMatch
	case sigv4.KindBodyUnreadable, sigv4.KindPayloadHashMismatch:
		code = queryapi.CodeInvalidParameterValue
	case sigv4.KindBodyTooLarge:
		status, code = http.StatusRequestEntityTooLarge, queryapi.CodeInvalidParameterValue
	case sigv4.KindKeyLookupFailed:
		// Not a client error: the store failed. ToError logs it and answers
		// with the service's internal error.
		return fmt.Errorf("look up the signing key: %w", e)
	}
	return queryapi.NewError(status, code, msg)
}
