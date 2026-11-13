package queryapi

import (
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"tule.dev/identity/internal/contracts"
)

// The tag rules of the IAM model: tagKeyType and tagValueType, and the 50
// items tagListType and tagKeyListType hold.
var (
	TagKey = Rule{
		min: 1, max: 128, source: `[\p{L}\p{Z}\p{N}_.:/=+\-@]+`,
		pattern: regexp.MustCompile(`^[\p{L}\p{Z}\p{N}_.:/=+\-@]+$`),
	}
	TagValue = Rule{
		min: 0, max: 256, source: `[\p{L}\p{Z}\p{N}_.:/=+\-@]*`,
		pattern: regexp.MustCompile(`^[\p{L}\p{Z}\p{N}_.:/=+\-@]*$`),
	}
)

const maxListItems = 50

// reservedTagPrefix starts the tag keys and values AWS keeps for its own
// use (the IAM User Guide, tagging IAM resources).
const reservedTagPrefix = "aws:"

// memberIndex is how the Query protocol spells a list member's index: an
// integer from 1 (the RDS and EC2 Query API guides: "integers starting from
// 1"), in decimal with no sign or leading zero. Each index then has one
// spelling, so no two parameters name the same member.
var memberIndex = regexp.MustCompile(`^[1-9][0-9]*$`)

// listMembers collects the members of the list parameter field, as the Query
// protocol sends them: field.member.N, or field.member.N.<name> for a list
// of structures. It returns the member values by index, each keyed by the
// part after the index ("" for a list of strings), and whether the request
// sets the list at all: an empty list is sent as field alone. An index
// spelled other than memberIndex allows is refused: read as a number, 01 or
// +1 would name member 1 as well, and which spelling's value won would
// depend on the order the parameters are read in.
func listMembers(p Params, field string) (map[int]map[string]string, bool, error) {
	members := map[int]map[string]string{}
	_, set := p.Get(field)
	prefix := field + ".member."
	for name := range p {
		rest, ok := strings.CutPrefix(name, prefix)
		if !ok {
			continue
		}
		set = true
		index, sub, _ := strings.Cut(rest, ".")
		n, err := strconv.Atoi(index)
		if err != nil || !memberIndex.MatchString(index) {
			return nil, true, ErrValidation(fmt.Sprintf(
				"%s is not a member of the list %s.", name, field))
		}
		if members[n] == nil {
			members[n] = map[string]string{}
		}
		members[n][sub], _ = p.Get(name)
	}
	if len(members) > maxListItems {
		return nil, true, ErrValidation(fmt.Sprintf(
			"1 validation error detected: Value at '%s' failed to satisfy constraint: "+
				"Member must have length less than or equal to %d", memberName(field), maxListItems))
	}
	return members, set, nil
}

// sortedIndexes returns the indexes of members in order.
func sortedIndexes[T any](members map[int]T) []int {
	indexes := make([]int, 0, len(members))
	for n := range members {
		indexes = append(indexes, n)
	}
	slices.Sort(indexes)
	return indexes
}

// Tags reads a list of tags, field.member.N.Key and field.member.N.Value,
// and checks each against the model and AWS's tagging rules: no key or value
// that begins with aws:, and no key twice without regard to case, by
// strings.EqualFold, since a user's tag keys are unique that way. It reports
// whether the request sets the list.
func Tags(p Params, field string) ([]contracts.Tag, bool, error) {
	members, set, err := listMembers(p, field)
	if err != nil || !set {
		return nil, set, err
	}
	tags := make([]contracts.Tag, 0, len(members))
	for _, n := range sortedIndexes(members) {
		t, tErr := tagOf(members[n], fmt.Sprintf("%s.%d.member", memberName(field), n))
		if tErr != nil {
			return nil, true, tErr
		}
		if slices.ContainsFunc(tags, func(o contracts.Tag) bool {
			return strings.EqualFold(o.Key, t.Key)
		}) {
			return nil, true, ErrInvalidInput(
				"Duplicate tag keys found. Tag keys are not case sensitive.")
		}
		tags = append(tags, t)
	}
	return tags, true, nil
}

// tagOf checks the Key and Value of the list member named item.
func tagOf(m map[string]string, item string) (contracts.Tag, error) {
	key, ok := m["Key"]
	if !ok {
		return contracts.Tag{}, errNull(item + ".key")
	}
	if err := TagKey.Check(item+".key", key); err != nil {
		return contracts.Tag{}, err
	}
	value, ok := m["Value"]
	if !ok {
		return contracts.Tag{}, errNull(item + ".value")
	}
	if err := TagValue.Check(item+".value", value); err != nil {
		return contracts.Tag{}, err
	}
	if reserved(key) || reserved(value) {
		return contracts.Tag{}, ErrInvalidInput("Tag keys and values can't begin with the " +
			"reserved prefix " + reservedTagPrefix + ".")
	}
	return contracts.Tag{Key: key, Value: value}, nil
}

func reserved(s string) bool {
	return strings.HasPrefix(strings.ToLower(s), reservedTagPrefix)
}

// TagKeys reads the required list of tag keys field.member.N.
func TagKeys(p Params, field string) ([]string, error) {
	members, set, err := listMembers(p, field)
	if err != nil {
		return nil, err
	}
	if !set {
		return nil, errNull(field)
	}
	keys := make([]string, 0, len(members))
	for _, n := range sortedIndexes(members) {
		key := members[n][""]
		if err = TagKey.Check(fmt.Sprintf("%s.%d.member", memberName(field), n), key); err != nil {
			return nil, err
		}
		keys = append(keys, key)
	}
	return keys, nil
}
