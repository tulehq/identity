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
