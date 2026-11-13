package sdkimpl

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"tule.dev/identity/internal/contracts"
)

const (
	orgID   = "o-a1b2c3d4e5"
	rootID  = "r-ab12"
	outerOU = "ou-ab12-11111111"
	innerOU = "ou-ab12-22222222"
	member  = "111111111111"
)

// fakeOrgs is a fake Organizations endpoint, speaking the JSON 1.1
// protocol the SDK client does: each operation named by X-Amz-Target is
// answered by its handler, with a status and a JSON body.
type fakeOrgs struct {
	ops   map[string]func(in map[string]string) (int, string)
	calls map[string]int
	mu    sync.Mutex
}

func (o *fakeOrgs) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	op := strings.TrimPrefix(r.Header.Get("X-Amz-Target"), "AWSOrganizationsV20161128.")
	var in map[string]string
	_ = json.NewDecoder(r.Body).Decode(&in)
	o.mu.Lock()
	o.calls[op]++
	o.mu.Unlock()
	handle, ok := o.ops[op]
	if !ok {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"__type":"InvalidInputException","Message":"unknown operation"}`))
		return
	}
	status, body := handle(in)
	w.Header().Set("Content-Type", "application/x-amz-json-1.1")
	w.WriteHeader(status)
	_, _ = w.Write([]byte(body))
}

// parent answers a ListParents with one parent of the type.
func parent(id, typ string) (int, string) {
	return http.StatusOK, `{"Parents":[{"Id":"` + id + `","Type":"` + typ + `"}]}`
}

// nested is an organization whose member sits in innerOU, under outerOU,
// under the root.
func nested() *fakeOrgs {
	return &fakeOrgs{calls: map[string]int{}, ops: map[string]func(map[string]string) (int, string){
		"DescribeOrganization": func(map[string]string) (int, string) {
			return http.StatusOK, `{"Organization":{"Id":"` + orgID + `","MasterAccountId":"000000000000"}}`
		},
		"DescribeAccount": func(in map[string]string) (int, string) {
			if in["AccountId"] != member {
				return http.StatusBadRequest, `{"__type":"AccountNotFoundException","Message":"no"}`
			}
			return http.StatusOK, `{"Account":{"Id":"` + member + `","State":"ACTIVE","Status":"ACTIVE"}}`
		},
		"ListParents": func(in map[string]string) (int, string) {
			switch in["ChildId"] {
			case member:
				return parent(innerOU, "ORGANIZATIONAL_UNIT")
			case innerOU:
				return parent(outerOU, "ORGANIZATIONAL_UNIT")
			default:
				return parent(rootID, "ROOT")
			}
		},
	}}
}

func directoryOf(t *testing.T, o *fakeOrgs) *Directory {
	t.Helper()
	srv := httptest.NewServer(o)
	t.Cleanup(srv.Close)
	return New(Settings{
		Endpoint: srv.URL, AccessKeyID: "AKIAIOSFODNN7EXAMPLE", SecretAccessKey: "secret",
	})
}

func TestOrganizationOfWalksUpToTheRoot(t *testing.T) {
	got, err := directoryOf(t, nested()).OrganizationOf(t.Context(), member)
	want := contracts.Organization{
		ID: orgID, Path: orgID + "/" + rootID + "/" + outerOU + "/" + innerOU + "/",
	}
	if err != nil || got != want {
		t.Fatalf("organization = %+v, %v; want %+v", got, err, want)
	}
}

func TestOrganizationOfAnAccountOutsideIsNone(t *testing.T) {
	for name, setup := range map[string]func(o *fakeOrgs){
		"not a member": func(o *fakeOrgs) {
			o.ops["DescribeAccount"] = func(map[string]string) (int, string) {
				return http.StatusBadRequest, `{"__type":"AccountNotFoundException","Message":"no"}`
			}
		},
		"suspended": func(o *fakeOrgs) {
			o.ops["DescribeAccount"] = func(map[string]string) (int, string) {
				return http.StatusOK, `{"Account":{"Id":"` + member + `","State":"SUSPENDED"}}`
			}
		},
		"no organization": func(o *fakeOrgs) {
			o.ops["DescribeOrganization"] = func(map[string]string) (int, string) {
				return http.StatusBadRequest,
					`{"__type":"AWSOrganizationsNotInUseException","Message":"no"}`
			}
		},
	} {
		o := nested()
		setup(o)
		got, err := directoryOf(t, o).OrganizationOf(t.Context(), member)
		if err != nil || got != (contracts.Organization{}) {
			t.Errorf("%s: organization = %+v, %v; want none", name, got, err)
		}
		if o.calls["ListParents"] != 0 {
			t.Errorf("%s: the parents were listed", name)
		}
	}
}

func TestOrganizationOfRefusesABadTree(t *testing.T) {
	for name, listParents := range map[string]func(map[string]string) (int, string){
		"no parent": func(map[string]string) (int, string) {
			return http.StatusOK, `{"Parents":[]}`
		},
		"two parents": func(map[string]string) (int, string) {
			return http.StatusOK, `{"Parents":[{"Id":"` + rootID + `","Type":"ROOT"},` +
				`{"Id":"` + outerOU + `","Type":"ORGANIZATIONAL_UNIT"}]}`
		},
		"a failed call": func(map[string]string) (int, string) {
			return http.StatusInternalServerError, `{"__type":"ServiceException","Message":"down"}`
		},
		"no root within the cap": func(map[string]string) (int, string) {
			return parent(outerOU, "ORGANIZATIONAL_UNIT")
		},
	} {
		o := nested()
		o.ops["ListParents"] = listParents
		got, err := directoryOf(t, o).OrganizationOf(t.Context(), member)
		if err == nil || got != (contracts.Organization{}) {
			t.Errorf("%s: organization = %+v, %v; want an error", name, got, err)
		}
		if errors.Is(err, contracts.ErrAccountNotFound) {
			t.Errorf("%s: %v is an account not found; want a failure", name, err)
		}
		if name == "no root within the cap" && o.calls["ListParents"] != maxDepth {
			t.Errorf("%s: %d ListParents calls; want the cap, %d", name,
				o.calls["ListParents"], maxDepth)
		}
	}
}

func TestOrganizationOfWithoutAnAccountsService(t *testing.T) {
	_, err := New(Settings{}).OrganizationOf(t.Context(), member)
	if !errors.Is(err, contracts.ErrNoAccountDirectory) {
		t.Fatalf("err = %v; want ErrNoAccountDirectory", err)
	}
}
