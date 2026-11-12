package queryapi

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/go-chi/chi/v5/middleware"

	"tule.dev/identity/internal/contracts"
)

func requestWithID(id string) *http.Request {
	r := httptest.NewRequest(http.MethodPost, "/", http.NoBody)
	return r.WithContext(context.WithValue(r.Context(), middleware.RequestIDKey, id))
}

func TestAnErrorIsAQueryErrorDocument(t *testing.T) {
	w := httptest.NewRecorder()
	WriteHTTPError(w, requestWithID("req-1"), IAM, ErrNoSuchUser("bob"))

	want := `<ErrorResponse xmlns="https://iam.amazonaws.com/doc/2010-05-08/">` +
		`<Error><Type>Sender</Type><Code>NoSuchEntity</Code>` +
		`<Message>The user with name bob cannot be found.</Message></Error>` +
		`<RequestId>req-1</RequestId></ErrorResponse>`
	if got := w.Body.String(); got != want {
		t.Fatalf("body = %s\nwant   %s", got, want)
	}
	if w.Code != http.StatusNotFound || w.Header().Get("Content-Type") != ContentType ||
		w.Header().Get(requestIDHeader) != "req-1" {
		t.Fatalf("status %d, headers %v", w.Code, w.Header())
	}
}

func TestAnUnknownFailureIsTheServicesInternalError(t *testing.T) {
	for _, tt := range []struct {
		svc  *Service
		code string
	}{
		{IAM, CodeServiceFailure},
		{STS, CodeInternalFailure},
		{nil, CodeInternalFailure},
	} {
		w := httptest.NewRecorder()
		WriteHTTPError(w, requestWithID("r"), tt.svc, errors.New("disk on fire"))
		body := w.Body.String()
		if w.Code != http.StatusInternalServerError ||
			!strings.Contains(body, "<Type>Receiver</Type><Code>"+tt.code+"</Code>") ||
			strings.Contains(body, "disk on fire") {
			t.Fatalf("%v: status %d, body %s", tt.svc, w.Code, body)
		}
	}
}

func TestStoreSentinelsMapToTheirErrors(t *testing.T) {
	tests := []struct {
		err    error
		code   string
		status int
	}{
		{contracts.ErrDeleteConflict, CodeDeleteConflict, http.StatusConflict},
		{contracts.ErrAccessKeyLimitExceeded, CodeLimitExceeded, http.StatusConflict},
		{contracts.ErrInvalidMarker, CodeInvalidInput, http.StatusBadRequest},
	}
	for _, tt := range tests {
		got := ToError(context.Background(), IAM, fmt.Errorf("wrapped: %w", tt.err))
		if got.Code != tt.code || got.Status != tt.status {
			t.Errorf("%v = %+v, want %s %d", tt.err, got, tt.code, tt.status)
		}
	}
}

func TestTheIAMCodesAreTheSDKs(t *testing.T) {
	// The SDK decodes an error into its modeled type by this code, so a code
	// that drifts from the model would surface as a generic API error.
	tests := []struct {
		sdk  interface{ ErrorCode() string }
		code string
	}{
		{&iamtypes.NoSuchEntityException{}, CodeNoSuchEntity},
		{&iamtypes.EntityAlreadyExistsException{}, CodeEntityAlreadyExists},
		{&iamtypes.DeleteConflictException{}, CodeDeleteConflict},
		{&iamtypes.LimitExceededException{}, CodeLimitExceeded},
		{&iamtypes.InvalidInputException{}, CodeInvalidInput},
		{&iamtypes.ServiceFailureException{}, CodeServiceFailure},
	}
	for _, tt := range tests {
		if got := tt.sdk.ErrorCode(); got != tt.code {
			t.Errorf("%T code = %s, want %s", tt.sdk, got, tt.code)
		}
	}
}

func TestTheServiceIsRoutedByItsSigningName(t *testing.T) {
	for name, want := range map[string]*Service{"iam": IAM, "sts": STS, "s3": nil, "": nil} {
		if got := ServiceNamed(name); got != want {
			t.Errorf("ServiceNamed(%q) = %v, want %v", name, got, want)
		}
	}
	ctx := WithService(context.Background(), STS)
	if got := ServiceFrom(ctx); got != STS {
		t.Fatalf("ServiceFrom = %v, want STS", got)
	}
	if got := ServiceFrom(context.Background()); got != nil {
		t.Fatalf("ServiceFrom of a bare context = %v, want nil", got)
	}
}

func params(q string) Params {
	v, err := url.ParseQuery(q)
	if err != nil {
		panic(err)
	}
	return Params(v)
}

func TestRulesAnswerAsTheQueryServicesDo(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
		rule Rule
	}{
		{
			name: "missing", rule: UserName, in: "",
			want: "1 validation error detected: Value null at 'userName' failed to satisfy " +
				"constraint: Member must not be null",
		},
		{
			name: "too long", rule: UserName, in: "UserName=" + strings.Repeat("a", 65),
			want: "Member must have length less than or equal to 64",
		},
		{
			name: "empty", rule: UserName, in: "UserName=",
			want: "Member must have length greater than or equal to 1",
		},
		{
			name: "pattern", rule: UserName, in: "UserName=a%20b",
			want: `Value 'a b' at 'userName' failed to satisfy constraint: Member must ` +
				`satisfy regular expression pattern: [\w+=,.@-]+`,
		},
		{name: "valid", rule: UserName, in: "UserName=a.b@c%2Bd=e,f-g_h"},
		{
			name: "existing name may be longer", rule: ExistingUserName,
			in: "UserName=" + strings.Repeat("a", 128),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := tt.rule.Required(params(tt.in), "UserName")
			if tt.want == "" {
				if err != nil {
					t.Fatalf("got %v, want no error", err)
				}
				return
			}
			var e *Error
			if !errors.As(err, &e) || e.Code != CodeValidation ||
				!strings.Contains(e.Message, tt.want) {
				t.Fatalf("got %v, want ValidationError containing %q", err, tt.want)
			}
		})
	}
}

func TestPathRules(t *testing.T) {
	for path, ok := range map[string]bool{
		"/": true, "/a/": true, "/a/b/": true, "/a": false, "a/": false, "//": false,
		"/a b/": false,
	} {
		err := Path.Check("Path", path)
		if (err == nil) != ok {
			t.Errorf("path %q: err = %v, want valid %v", path, err, ok)
		}
	}
	for prefix, ok := range map[string]bool{"/": true, "/a": true, "a": false} {
		err := PathPrefix.Check("PathPrefix", prefix)
		if (err == nil) != ok {
			t.Errorf("prefix %q: err = %v, want valid %v", prefix, err, ok)
		}
	}
}

func TestPageBounds(t *testing.T) {
	if _, n, err := Page(params("")); err != nil || n != DefaultMaxItems {
		t.Fatalf("default page = %d, %v", n, err)
	}
	for _, q := range []string{"MaxItems=0", "MaxItems=1001", "MaxItems=x", "Marker="} {
		if _, _, err := Page(params(q)); err == nil {
			t.Errorf("%s accepted", q)
		}
	}
}

func TestEnum(t *testing.T) {
	if _, err := Enum(params("Status=Active"), "Status", "Active", "Inactive"); err != nil {
		t.Fatalf("Active: %v", err)
	}
	_, err := Enum(params("Status=active"), "Status", "Active", "Inactive")
	if err == nil || !strings.Contains(err.Error(), "enum value set: [Active, Inactive]") {
		t.Fatalf("active: %v", err)
	}
}
