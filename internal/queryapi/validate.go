package queryapi

import (
	"fmt"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"
)

// Params are the parameters of a request: its form fields, which the Query
// protocol puts in the body.
type Params url.Values

// Get returns a parameter's value and whether the request sets it. The
// protocol sends an empty string for a parameter set to "", so the two can
// be told apart.
func (p Params) Get(name string) (string, bool) {
	vs, ok := p[name]
	if !ok || len(vs) == 0 {
		return "", false
	}
	return vs[0], true
}

// HasPrefix reports whether the request sets any parameter whose name
// starts with prefix, as the members of a list or structure parameter do
// ("Tags.member.1.Key").
func (p Params) HasPrefix(prefix string) bool {
	for name := range p {
		if strings.HasPrefix(name, prefix) {
			return true
		}
	}
	return false
}

// Rule is the length and pattern a string parameter must meet, as the API
// model states them. Lengths count characters, and the pattern must match
// the whole value; source is the pattern as the model spells it, for the
// message.
type Rule struct {
	pattern *regexp.Regexp
	source  string
	min     int
	max     int
}

func rule(minLen, maxLen int, pattern string) Rule {
	r := Rule{min: minLen, max: maxLen, source: pattern}
	if pattern != "" {
		r.pattern = regexp.MustCompile(`^(?:` + pattern + `)$`)
	}
	return r
}

// The parameter rules of the in-scope operations, from the IAM and STS
// models. The model writes some characters as \uXXXX escapes, which Go's
// regexp spells \x{XXXX}; the source kept for the message is the model's.
var (
	// UserName is userNameType, the name CreateUser takes.
	UserName = rule(1, 64, `[\w+=,.@-]+`)
	// ExistingUserName is existingUserNameType, the name the other
	// operations look a user up by.
	ExistingUserName = rule(1, 128, `[\w+=,.@-]+`)
	// Path is pathType: "/" alone, or a string that begins and ends with
	// "/".
	Path = Rule{
		min: 1, max: 512, source: `(/)|(/[!-~]+/)`,
		pattern: regexp.MustCompile(`^(?:/|/[\x{21}-\x{7E}]+/)$`),
	}
	// PathPrefix is pathPrefixType.
	PathPrefix = Rule{
		min: 1, max: 512, source: `/[!-\u007F]*`,
		pattern: regexp.MustCompile(`^/[\x{21}-\x{7F}]*$`),
	}
	// Marker is markerType.
	Marker = Rule{
		min: 1, max: 320, source: `[ -ÿ]+`,
		pattern: regexp.MustCompile(`^[\x{20}-\x{FF}]+$`),
	}
	// AccessKeyID is accessKeyIdType.
	AccessKeyID = rule(16, 128, `[\w]+`)
	// RoleARN is AssumeRole's arnType; its pattern admits every character
	// but a few control characters, and the RoleArn check that matters is
	// whether it names the one role this service has.
	RoleARN = rule(20, 2048, "")
	// RoleSessionName is roleSessionNameType.
	RoleSessionName = rule(2, 64, `[\w+=,.@-]*`)
)

// errConstraint is the ValidationError for a parameter that breaks a
// constraint, in the message form of the Query services.
func errConstraint(field, value, constraint string) *Error {
	return ErrValidation(fmt.Sprintf(
		"1 validation error detected: Value '%s' at '%s' failed to satisfy constraint: "+
			"Member must %s", value, memberName(field), constraint))
}

// errNull is the ValidationError for a required parameter the request
// leaves out.
func errNull(field string) *Error {
	return ErrValidation(fmt.Sprintf(
		"1 validation error detected: Value null at '%s' failed to satisfy constraint: "+
			"Member must not be null", memberName(field)))
}

// memberName is how the services name a parameter in a validation message:
// its wire name with the first letter lowered (UserName, userName).
func memberName(field string) string {
	if field == "" {
		return field
	}
	return strings.ToLower(field[:1]) + field[1:]
}

// Required reads a parameter the operation requires and checks it against
// r.
func (r Rule) Required(p Params, field string) (string, error) {
	v, ok := p.Get(field)
	if !ok {
		return "", errNull(field)
	}
	return v, r.Check(field, v)
}

// Optional reads a parameter the operation may leave out, checking it
// against r when it is set. It returns "" when the request leaves it out.
func (r Rule) Optional(p Params, field string) (string, error) {
	v, ok := p.Get(field)
	if !ok {
		return "", nil
	}
	return v, r.Check(field, v)
}

// Check checks a value that is present against r.
func (r Rule) Check(field, v string) error {
	n := utf8.RuneCountInString(v)
	switch {
	case n < r.min:
		return errConstraint(field, v,
			fmt.Sprintf("have length greater than or equal to %d", r.min))
	case n > r.max:
		return errConstraint(field, v,
			fmt.Sprintf("have length less than or equal to %d", r.max))
	case r.pattern != nil && !r.pattern.MatchString(v):
		return errConstraint(field, v, "satisfy regular expression pattern: "+r.source)
	}
	return nil
}

// Enum reads a required parameter that must be one of values.
func Enum(p Params, field string, values ...string) (string, error) {
	v, ok := p.Get(field)
	if !ok {
		return "", errNull(field)
	}
	for _, want := range values {
		if v == want {
			return v, nil
		}
	}
	return "", errConstraint(field, v,
		"satisfy enum value set: ["+strings.Join(values, ", ")+"]")
}

// Int reads an optional integer parameter in [minValue, maxValue]. It
// returns 0 and false when the request leaves it out.
func Int(p Params, field string, minValue, maxValue int) (int, bool, error) {
	v, ok := p.Get(field)
	if !ok {
		return 0, false, nil
	}
	n, err := strconv.Atoi(v)
	switch {
	case err != nil:
		return 0, false, errConstraint(field, v, "be an integer")
	case n < minValue:
		return 0, false, errConstraint(field, v,
			fmt.Sprintf("have value greater than or equal to %d", minValue))
	case n > maxValue:
		return 0, false, errConstraint(field, v,
			fmt.Sprintf("have value less than or equal to %d", maxValue))
	}
	return n, true, nil
}

// The MaxItems bounds and default of the IAM list operations: maxItemsType
// is 1 to 1000, and the model documents a default of 100.
const (
	maxItemsMin     = 1
	maxItemsMax     = 1000
	DefaultMaxItems = 100
)

// Page reads the Marker and MaxItems of an IAM list request. MaxItems is
// DefaultMaxItems when the request sets none.
func Page(p Params) (marker string, maxItems int, err error) {
	if marker, err = Marker.Optional(p, "Marker"); err != nil {
		return "", 0, err
	}
	n, ok, err := Int(p, "MaxItems", maxItemsMin, maxItemsMax)
	if err != nil {
		return "", 0, err
	}
	if !ok {
		n = DefaultMaxItems
	}
	return marker, n, nil
}
