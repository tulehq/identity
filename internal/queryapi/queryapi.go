// Package queryapi is the IAM and STS wire layer: the AWS Query protocol both
// speak, a form-encoded POST / naming its operation in Action and its API
// version in Version and answered in XML, the response and error documents,
// and the input validation the service applies before a request reaches the
// store.
//
// One server serves both APIs. A request is IAM's or STS's by the service its
// verified SigV4 credential is scoped to, which the SDKs set from the
// client's signing name, so the two cannot be told apart by anything else on
// the wire.
package queryapi

import (
	"bytes"
	"context"
	"encoding/xml"
	"net/http"

	"github.com/gasmod/gas"

	"tule.dev/identity/internal/httpx"
)

// Service is one of the two APIs this server speaks.
type Service struct {
	// Name is the SigV4 signing name a credential is scoped to.
	Name string
	// Version is the API version every request names in Version.
	Version string
	// Namespace is the XML namespace of every response document.
	Namespace string
	// internalError is the code an unrecognized failure is answered with.
	internalError string
}

// The two services, as their API models describe them.
var (
	IAM = &Service{
		Name:          "iam",
		Version:       "2010-05-08",
		Namespace:     "https://iam.amazonaws.com/doc/2010-05-08/",
		internalError: CodeServiceFailure,
	}
	STS = &Service{
		Name:          "sts",
		Version:       "2011-06-15",
		Namespace:     "https://sts.amazonaws.com/doc/2011-06-15/",
		internalError: CodeInternalFailure,
	}
)

// ContentType is the media type of every response document. AWS answers
// Query requests with text/xml.
const ContentType = "text/xml"

// requestIDHeader is where AWS reports the ID of a request, beside the
// RequestId in the document.
const requestIDHeader = "X-Amzn-Requestid"

// ServiceNamed returns the service whose signing name is name, or nil when
// it is neither IAM's nor STS's.
func ServiceNamed(name string) *Service {
	switch name {
	case IAM.Name:
		return IAM
	case STS.Name:
		return STS
	default:
		return nil
	}
}

type serviceKey struct{}

// WithService returns ctx carrying svc, the service of the request's
// verified credential scope, for the dispatcher to route on.
func WithService(ctx context.Context, svc *Service) context.Context {
	return context.WithValue(ctx, serviceKey{}, svc)
}

// ServiceFrom returns the service ctx carries, or nil when it carries none:
// the request's credential is scoped to neither IAM nor STS.
func ServiceFrom(ctx context.Context) *Service {
	svc, _ := ctx.Value(serviceKey{}).(*Service)
	return svc
}

// responseMetadata closes every successful response document.
type responseMetadata struct {
	RequestID string `xml:"RequestId"`
}

// Write sends result as the <op>Result of a successful response to op, in
// svc's document. A nil result writes no Result element, as AWS answers the
// operations that return nothing.
func Write(ctx gas.Context, svc *Service, op string, result any) error {
	r := ctx.Request()
	var buf bytes.Buffer
	enc := xml.NewEncoder(&buf)
	root := xml.StartElement{
		Name: xml.Name{Local: op + "Response"},
		Attr: []xml.Attr{{Name: xml.Name{Local: "xmlns"}, Value: svc.Namespace}},
	}
	err := enc.EncodeToken(root)
	if err == nil && result != nil {
		err = enc.EncodeElement(result, xml.StartElement{Name: xml.Name{Local: op + "Result"}})
	}
	if err == nil {
		err = enc.EncodeElement(responseMetadata{RequestID: httpx.RequestIDOf(r.Context())},
			xml.StartElement{Name: xml.Name{Local: "ResponseMetadata"}})
	}
	if err == nil {
		err = enc.EncodeToken(root.End())
	}
	if err == nil {
		err = enc.Flush()
	}
	if err != nil {
		return WriteError(ctx, svc, err)
	}

	w := ctx.ResponseWriter()
	w.Header().Set("Content-Type", ContentType)
	setRequestID(w, r)
	w.WriteHeader(http.StatusOK)
	if _, wErr := w.Write(buf.Bytes()); wErr != nil {
		httpx.Logger(r.Context()).Warn("failed to write response").Err("error", wErr).Send()
	}
	return nil
}

func setRequestID(w http.ResponseWriter, r *http.Request) {
	if id := httpx.RequestIDOf(r.Context()); id != "" {
		w.Header().Set(requestIDHeader, id)
	}
}
