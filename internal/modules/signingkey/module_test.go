package signingkey

import (
	"context"
	"errors"
	"testing"

	"tule.dev/identity/internal/orgkeys"
	"tule.dev/identity/keysource"
)

// orgSource answers every account with keys and err.
type orgSource struct {
	err  error
	keys orgkeys.Keys
}

func (s orgSource) For(context.Context, string) (orgkeys.Keys, error) {
	return s.keys, s.err
}

func TestAFailedLookupIsReportedUnknown(t *testing.T) {
	// Whatever keys come with the error, the principal is reported with
	// its organization unknown and neither key.
	m := NewModule(nil, nil, orgSource{
		keys: orgkeys.Keys{OrgID: "o-a1b2c3d4e5", Paths: []string{"o-a1b2c3d4e5/r-ab12/"}},
		err:  errors.New("down"),
	})
	p := &keysource.Principal{AccountID: "123456789012"}
	m.addOrganization(t.Context(), p)
	if !p.OrgUnknown || p.OrgID != "" || p.OrgPaths != nil {
		t.Fatalf("principal %+v; want the organization unknown", p)
	}
}
