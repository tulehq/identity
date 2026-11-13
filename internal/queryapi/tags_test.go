package queryapi

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestTagsAreReadInListOrder(t *testing.T) {
	tags, set, err := Tags(params(
		"Tags.member.2.Key=b&Tags.member.2.Value=&Tags.member.1.Key=a&Tags.member.1.Value=1"),
		"Tags")
	if err != nil || !set || fmt.Sprint(tags) != "[{a 1} {b }]" {
		t.Fatalf("tags = %v, set %v, err %v", tags, set, err)
	}

	tags, set, err = Tags(params("Tags="), "Tags")
	if err != nil || !set || len(tags) != 0 {
		t.Fatalf("empty list: tags = %v, set %v, err %v", tags, set, err)
	}
	if _, set, err = Tags(params("UserName=x"), "Tags"); set || err != nil {
		t.Fatalf("no list: set %v, err %v", set, err)
	}
}

func TestTagsAnswerAsTheModelRules(t *testing.T) {
	var fifty strings.Builder
	for i := 1; i <= 51; i++ {
		fmt.Fprintf(&fifty, "&Tags.member.%d.Key=k%d&Tags.member.%d.Value=v", i, i, i)
	}
	tests := []struct {
		name, query, code, text string
	}{
		{"no value", "Tags.member.1.Key=a", CodeValidation, "'tags.1.member.value'"},
		{"no key", "Tags.member.1.Value=a", CodeValidation, "'tags.1.member.key'"},
		{
			"long key", "Tags.member.1.Key=" + strings.Repeat("k", 129) + "&Tags.member.1.Value=v",
			CodeValidation, "less than or equal to 128",
		},
		{"bad index", "Tags.member.x.Key=a", CodeValidation, "not a member"},
		{"too many", fifty.String()[1:], CodeValidation, "less than or equal to 50"},
		{"reserved", "Tags.member.1.Key=AWS:x&Tags.member.1.Value=v", CodeInvalidInput, "aws:"},
		{
			"duplicate", "Tags.member.1.Key=Env&Tags.member.1.Value=1" +
				"&Tags.member.2.Key=env&Tags.member.2.Value=2", CodeInvalidInput, "Duplicate tag keys",
		},
		// Keys are folded beyond ASCII, as strings.EqualFold folds them: Ä is ä.
		{
			"duplicate beyond ASCII", "Tags.member.1.Key=%C3%84&Tags.member.1.Value=1" +
				"&Tags.member.2.Key=%C3%A4&Tags.member.2.Value=2", CodeInvalidInput, "Duplicate tag keys",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, err := Tags(params(tt.query), "Tags")
			var e *Error
			if !errors.As(err, &e) || e.Code != tt.code || !strings.Contains(e.Message, tt.text) {
				t.Fatalf("got %v, want %s containing %q", err, tt.code, tt.text)
			}
		})
	}
}

func TestTagKeys(t *testing.T) {
	keys, err := TagKeys(params("TagKeys.member.1=a&TagKeys.member.2=b"), "TagKeys")
	if err != nil || fmt.Sprint(keys) != "[a b]" {
		t.Fatalf("keys = %v, err %v", keys, err)
	}
	if _, err = TagKeys(params(""), "TagKeys"); err == nil {
		t.Fatal("a missing TagKeys was accepted")
	}
}

// An index has one spelling, an integer from 1 with no sign or leading
// zero. Read as a number, 01 and +1 would name member 1 too, and the member
// would take whichever spelling's value was read last, in an order that
// changes from one read to the next.
func TestAMemberIndexHasOneSpelling(t *testing.T) {
	for _, index := range []string{"01", "+1", "0", "-1", "001", "%2B1", "1%20", "0x1"} {
		t.Run(index, func(t *testing.T) {
			// Alone, and beside member 1's own spelling, which it would alias.
			for _, query := range []string{
				"Tags.member." + index + ".Key=env&Tags.member." + index + ".Value=prod",
				"Tags.member.1.Key=env&Tags.member.1.Value=dev&Tags.member." + index +
					".Value=prod",
			} {
				_, _, err := Tags(params(query), "Tags")
				var e *Error
				if !errors.As(err, &e) || e.Code != CodeValidation ||
					!strings.Contains(e.Message, "not a member") {
					t.Fatalf("Tags(%q) = %v, want a %s", query, err, CodeValidation)
				}
			}
			query := "TagKeys.member.1=env&TagKeys.member." + index + "=team"
			if _, err := TagKeys(params(query), "TagKeys"); err == nil {
				t.Fatalf("TagKeys(%q) was accepted", query)
			}
		})
	}

	tags, _, err := Tags(params("Tags.member.10.Key=b&Tags.member.10.Value=2&"+
		"Tags.member.9.Key=a&Tags.member.9.Value=1"), "Tags")
	if err != nil || fmt.Sprint(tags) != "[{a 1} {b 2}]" {
		t.Fatalf("multi-digit indexes: tags = %v, err %v", tags, err)
	}
}
