package query

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"tule.dev/identity/internal/contracts"
	"tule.dev/identity/internal/orgkeys"
)

// orgSource answers every account with keys and err.
type orgSource struct {
	err  error
	keys orgkeys.Keys
}

func (s orgSource) For(context.Context, string) (orgkeys.Keys, error) {
	return s.keys, s.err
}

var memberKeys = orgkeys.Keys{OrgID: "o-a1b2c3d4e5", Paths: []string{"o-a1b2c3d4e5/r-ab12/"}}

func TestAFailedLookupMakesTheOrganizationKeysUnknown(t *testing.T) {
	// Whatever keys come with the error, the evaluation takes them as
	// unknown and supplies none.
	m := NewModule(nil, nil, nil, orgSource{keys: memberKeys, err: errors.New("down")})
	c := &call{caller: &contracts.Principal{AccountID: "123456789012"}}
	keys := map[string][]string{}
	unknown := m.addOrgKeys(t.Context(), c, keys)
	if !reflect.DeepEqual(unknown, orgKeyNames) || len(keys) != 0 || !c.org.Unknown {
		t.Fatalf("unknown %v, keys %v, org %+v; want both keys unknown and none supplied",
			unknown, keys, c.org)
	}
}

func TestKnownOrganizationKeysAreSupplied(t *testing.T) {
	m := NewModule(nil, nil, nil, orgSource{keys: memberKeys})
	c := &call{caller: &contracts.Principal{AccountID: "123456789012"}}
	keys := map[string][]string{}
	if unknown := m.addOrgKeys(t.Context(), c, keys); unknown != nil {
		t.Fatalf("unknown %v; want none", unknown)
	}
	want := map[string][]string{
		"aws:PrincipalOrgID":    {memberKeys.OrgID},
		"aws:PrincipalOrgPaths": memberKeys.Paths,
	}
	if !reflect.DeepEqual(keys, want) {
		t.Fatalf("keys %v; want %v", keys, want)
	}
}
