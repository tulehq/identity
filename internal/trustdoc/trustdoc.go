// Package trustdoc rewrites the principals of a role's trust policy: to bind
// them to unique IDs as IAM does, and to show them as IAM shows them once a
// principal is gone. Only the values of Statement[].Principal.AWS change;
// every other member is kept as it was written, in its order.
package trustdoc

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"

	"tule.dev/identity/internal/contracts"
)

// member is one member of a JSON object, its value as it was written.
type member struct {
	key   string
	value json.RawMessage
}

// decodeObject reads a JSON object's members in order.
func decodeObject(raw []byte) ([]member, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	if tok, err := dec.Token(); err != nil || tok != json.Delim('{') {
		return nil, errors.New("not a JSON object")
	}
	var out []member
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return nil, fmt.Errorf("read a member name: %w", err)
		}
		key, ok := tok.(string)
		if !ok {
			return nil, errors.New("a member name is not a string")
		}
		var v json.RawMessage
		if err = dec.Decode(&v); err != nil {
			return nil, fmt.Errorf("read the member %s: %w", key, err)
		}
		out = append(out, member{key: key, value: v})
	}
	return out, nil
}

func encodeObject(ms []member) json.RawMessage {
	var b bytes.Buffer
	b.WriteByte('{')
	for i, m := range ms {
		if i > 0 {
			b.WriteByte(',')
		}
		key, _ := marshalString(m.key)
		b.Write(key)
		b.WriteByte(':')
		b.Write(m.value)
	}
	b.WriteByte('}')
	return b.Bytes()
}

// marshalString writes a string as JSON, without escaping <, > and &.
func marshalString(v any) ([]byte, error) {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, fmt.Errorf("encode: %w", err)
	}
	return bytes.TrimRight(b.Bytes(), "\n"), nil
}

// RewritePrincipals returns doc with each AWS principal value replaced by
// fn's answer for it, and whether any changed. doc is a trust policy that
// parsed.
func RewritePrincipals(doc string, fn func(string) string) (string, bool, error) {
	top, err := decodeObject([]byte(doc))
	if err != nil {
		return "", false, fmt.Errorf("trustdoc: read the trust policy: %w", err)
	}
	changed := false
	for i, m := range top {
		if m.key != "Statement" {
			continue
		}
		v, c, sErr := rewriteStatements(m.value, fn)
		if sErr != nil {
			return "", false, sErr
		}
		top[i].value, changed = v, changed || c
	}
	if !changed {
		return doc, false, nil
	}
	return string(encodeObject(top)), true, nil
}

// rewriteStatements rewrites a Statement element: one statement, or an
// array of them.
func rewriteStatements(raw json.RawMessage, fn func(string) string) (json.RawMessage, bool, error) {
	var list []json.RawMessage
	if json.Unmarshal(raw, &list) != nil {
		return rewriteStatement(raw, fn)
	}
	changed := false
	for i, st := range list {
		v, c, err := rewriteStatement(st, fn)
		if err != nil {
			return nil, false, err
		}
		list[i], changed = v, changed || c
	}
	if !changed {
		return raw, false, nil
	}
	return append(append([]byte{'['}, bytes.Join(asBytes(list), []byte{','})...), ']'), true, nil
}

func asBytes(list []json.RawMessage) [][]byte {
	out := make([][]byte, len(list))
	for i, v := range list {
		out[i] = v
	}
	return out
}

func rewriteStatement(raw json.RawMessage, fn func(string) string) (json.RawMessage, bool, error) {
	st, err := decodeObject(raw)
	if err != nil {
		return nil, false, fmt.Errorf("trustdoc: read a trust policy statement: %w", err)
	}
	changed := false
	for i, m := range st {
		if m.key != "Principal" {
			continue
		}
		v, c, pErr := rewritePrincipal(m.value, fn)
		if pErr != nil {
			return nil, false, pErr
		}
		st[i].value, changed = v, changed || c
	}
	if !changed {
		return raw, false, nil
	}
	return encodeObject(st), true, nil
}

// rewritePrincipal rewrites a Principal element's AWS values; "*" alone is
// kept.
func rewritePrincipal(raw json.RawMessage, fn func(string) string) (json.RawMessage, bool, error) {
	var all string
	if json.Unmarshal(raw, &all) == nil {
		return raw, false, nil
	}
	byType, err := decodeObject(raw)
	if err != nil {
		return nil, false, fmt.Errorf("trustdoc: read a trust policy principal: %w", err)
	}
	changed := false
	for i, t := range byType {
		if t.key != "AWS" {
			continue
		}
		v, c, aErr := rewriteValues(t.value, fn)
		if aErr != nil {
			return nil, false, aErr
		}
		byType[i].value, changed = v, changed || c
	}
	if !changed {
		return raw, false, nil
	}
	return encodeObject(byType), true, nil
}

// rewriteValues rewrites an AWS principal value: a string or an array of
// strings, keeping its shape.
func rewriteValues(raw json.RawMessage, fn func(string) string) (json.RawMessage, bool, error) {
	var one string
	if json.Unmarshal(raw, &one) == nil {
		if r := fn(one); r != one {
			v, err := marshalString(r)
			return v, true, err
		}
		return raw, false, nil
	}
	var many []string
	if err := json.Unmarshal(raw, &many); err != nil {
		return nil, false, fmt.Errorf("trustdoc: read an AWS principal: %w", err)
	}
	changed := false
	for i, v := range many {
		if r := fn(v); r != v {
			many[i], changed = r, true
		}
	}
	if !changed {
		return raw, false, nil
	}
	v, err := marshalString(many)
	return v, true, err
}

// BindablePrincipals returns the user and role ARNs a trust policy names, the
// principals IAM binds to unique IDs.
func BindablePrincipals(doc string) ([]string, error) {
	var out []string
	seen := map[string]bool{}
	_, _, err := RewritePrincipals(doc, func(v string) string {
		if contracts.IsBindable(v) && !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
		return v
	})
	return out, err
}

// namesNobody is the AWS principal AssumeRole evaluates in place of a user
// or role ARN that does not name the caller: an IAM ARN of the ARN's
// account, as tule.dev/policy requires of an AWS principal, but of a
// resource no caller is, so it matches nobody. id is the unique ID the ARN
// was bound to, or "none" for one saved without a binding.
func namesNobody(arn, id string) string {
	account, _, _, ok := contracts.ParseUserARN(arn)
	if !ok {
		account, _, _, _ = contracts.ParseRoleARN(arn)
	}
	return "arn:aws:iam::" + account + ":unbound/" + id
}

// ForCaller returns the role's trust policy as AssumeRole evaluates it for a
// caller whose unique ID is callerID: each user and role ARN names the
// caller only while its binding is the caller's ID, and otherwise names
// nobody. IAM matches a Principal by the unique ID it was bound to when the
// policy was saved, so a user or role created again with the ARN is not
// trusted.
func ForCaller(role *contracts.Role, callerID string) (string, error) {
	doc, _, err := RewritePrincipals(role.TrustPolicy, func(v string) string {
		if !contracts.IsBindable(v) {
			return v
		}
		b := role.BindingFor(v)
		switch {
		case b == nil:
			return namesNobody(v, "none")
		case callerID == "" || b.PrincipalID != callerID:
			return namesNobody(v, b.PrincipalID)
		}
		return v
	})
	return doc, err
}

// Shown returns the role's trust policy as GetRole and ListRoles show
// it: as saved, with the ARN of a principal no longer there replaced by the
// unique ID it was bound to, as IAM shows it once it "can no longer map it
// back to a valid ARN" ("AWS JSON policy elements: Principal").
func Shown(role *contracts.Role) (string, error) {
	stale := false
	for _, b := range role.TrustBindings {
		stale = stale || !b.Current
	}
	if !stale {
		return role.TrustPolicy, nil
	}
	doc, _, err := RewritePrincipals(role.TrustPolicy, func(v string) string {
		if b := role.BindingFor(v); b != nil && !b.Current {
			return b.PrincipalID
		}
		return v
	})
	return doc, err
}
