// Package strictyaml decodes YAML into a struct the way pydantic validates a
// model:
//   - A field is required unless its type is Optional[T], so the struct says
//     at a glance which keys may be left out.
//   - A key the struct has no field for is an error, not ignored, so a typo
//     such as deny_host can't quietly drop a setting.
//   - Values are checked as they are decoded: a type that implements
//     yaml.Unmarshaler validates itself, and a Validator is checked once it
//     has decoded.
//   - Every error is reported, not only the first, each with where it is: its
//     location as a dotted path (deny_addrs.1) and its line.
//
// Fields are matched by their yaml tag, or their name if they have none.
// Field types may be structs, slices, Optional, yaml.Unmarshaler, or anything
// yaml.v3 decodes from a scalar.
package strictyaml

import (
	"errors"
	"fmt"
	"reflect"
	"strconv"
	"strings"

	"go.yaml.in/yaml/v3"
)

// Optional is a field that may be left out, or set to null, which is the
// same. Get reports whether it was set.
type Optional[T any] struct {
	value T
	set   bool
}

// Some returns an Optional set to v.
func Some[T any](v T) Optional[T] { return Optional[T]{value: v, set: true} }

// Get returns the value and whether it was set.
func (o Optional[T]) Get() (T, bool) { return o.value, o.set }

// Or returns the value if it was set, and def otherwise.
func (o Optional[T]) Or(def T) T {
	if o.set {
		return o.value
	}
	return def
}

func (o *Optional[T]) target() any { o.set = true; return &o.value }

// optional is what the decoder sees of an Optional[T], whatever T is.
type optional interface {
	// target marks the field set and returns a pointer to its value.
	target() any
}

// Validator is a value that checks itself once it has decoded without errors,
// as a pydantic field_validator does, for a rule that is about the whole
// value, such as a list that mustn't be empty. A non-nil error is reported
// at the value's location.
type Validator interface {
	Validate() error
}

// FieldError is one value that doesn't validate.
type FieldError struct {
	Loc  string // dotted path, such as deny_addrs.1; empty for the document
	Line int
	Msg  string
}

func (e FieldError) String() string {
	loc := e.Loc
	if loc == "" {
		loc = "(document)"
	}
	return fmt.Sprintf("%s: %s (line %d)", loc, e.Msg, e.Line)
}

// ValidationError is every value in a document that doesn't validate, in the
// order they appear.
type ValidationError struct {
	Errors []FieldError
}

func (e *ValidationError) Error() string {
	var b strings.Builder
	if len(e.Errors) == 1 {
		b.WriteString("1 validation error")
	} else {
		fmt.Fprintf(&b, "%d validation errors", len(e.Errors))
	}
	for _, fe := range e.Errors {
		b.WriteString("\n  " + fe.String())
	}
	return b.String()
}

// Unmarshal decodes data into v, a pointer to a struct. A syntax error is
// returned as yaml.v3 reports it; anything that parses but doesn't fit v is
// a *ValidationError. An empty document is an empty mapping.
func Unmarshal(data []byte, v any) error {
	rv := reflect.ValueOf(v)
	if rv.Kind() != reflect.Pointer || rv.Elem().Kind() != reflect.Struct {
		return fmt.Errorf("strictyaml: Unmarshal needs a pointer to a struct, not %T", v)
	}
	var doc yaml.Node
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return err
	}
	root := &yaml.Node{Kind: yaml.MappingNode, Line: 1}
	if doc.Kind == yaml.DocumentNode && len(doc.Content) == 1 {
		root = doc.Content[0]
	}
	var d decoder
	d.value(root, rv.Elem(), "")
	if len(d.errs) > 0 {
		return &ValidationError{Errors: d.errs}
	}
	return nil
}

type decoder struct {
	errs []FieldError
}

func (d *decoder) fail(n *yaml.Node, loc, format string, args ...any) {
	d.errs = append(d.errs, FieldError{Loc: loc, Line: n.Line, Msg: fmt.Sprintf(format, args...)})
}

var unmarshalerType = reflect.TypeFor[yaml.Unmarshaler]()

func (d *decoder) value(n *yaml.Node, v reflect.Value, loc string) {
	if n.Kind == yaml.AliasNode {
		n = n.Alias
	}
	if opt, ok := v.Addr().Interface().(optional); ok {
		if !isNull(n) {
			d.value(n, reflect.ValueOf(opt.target()).Elem(), loc)
		}
		return
	}
	if isNull(n) {
		d.fail(n, loc, "should not be null")
		return
	}
	before := len(d.errs)
	d.decode(n, v, loc)
	if val, ok := v.Addr().Interface().(Validator); ok && len(d.errs) == before {
		if err := val.Validate(); err != nil {
			d.fail(n, loc, "%s", err)
		}
	}
}

func (d *decoder) decode(n *yaml.Node, v reflect.Value, loc string) {
	if v.Addr().Type().Implements(unmarshalerType) {
		if err := n.Decode(v.Addr().Interface()); err != nil {
			d.fail(n, loc, "%s", message(err))
		}
		return
	}
	switch v.Kind() {
	case reflect.Struct:
		d.object(n, v, loc)
	case reflect.Slice:
		if n.Kind != yaml.SequenceNode {
			d.fail(n, loc, "should be a list")
			return
		}
		s := reflect.MakeSlice(v.Type(), len(n.Content), len(n.Content))
		for i, item := range n.Content {
			d.value(item, s.Index(i), join(loc, strconv.Itoa(i)))
		}
		v.Set(s)
	default:
		if n.Kind != yaml.ScalarNode {
			d.fail(n, loc, "should be a %s", v.Type())
			return
		}
		if err := n.Decode(v.Addr().Interface()); err != nil {
			d.fail(n, loc, "%s", message(err))
		}
	}
}

func (d *decoder) object(n *yaml.Node, v reflect.Value, loc string) {
	if n.Kind != yaml.MappingNode {
		d.fail(n, loc, "should be a mapping")
		return
	}
	fields := map[string]int{}
	for i := range v.NumField() {
		if name, ok := fieldName(v.Type().Field(i)); ok {
			fields[name] = i
		}
	}
	seen := map[string]bool{}
	for i := 0; i+1 < len(n.Content); i += 2 {
		key, val := n.Content[i], n.Content[i+1]
		floc := join(loc, key.Value)
		idx, ok := fields[key.Value]
		switch {
		case !ok:
			d.fail(key, floc, "unknown field")
		case seen[key.Value]:
			d.fail(key, floc, "duplicate field")
		default:
			seen[key.Value] = true
			d.value(val, v.Field(idx), floc)
		}
	}
	for i := range v.NumField() {
		name, ok := fieldName(v.Type().Field(i))
		if !ok || seen[name] {
			continue
		}
		if _, opt := v.Field(i).Addr().Interface().(optional); !opt {
			d.fail(n, join(loc, name), "field required")
		}
	}
}

// fieldName is the key a struct field is decoded from, if it is decoded.
func fieldName(f reflect.StructField) (string, bool) {
	if !f.IsExported() {
		return "", false
	}
	name, _, _ := strings.Cut(f.Tag.Get("yaml"), ",")
	switch name {
	case "-":
		return "", false
	case "":
		return f.Name, true
	}
	return name, true
}

func isNull(n *yaml.Node) bool {
	return n.Kind == yaml.ScalarNode && n.Tag == "!!null"
}

func join(loc, name string) string {
	if loc == "" {
		return name
	}
	return loc + "." + name
}

// message is err without the "yaml: unmarshal errors: line N:" yaml.v3 puts
// in front of a type error; the line is in the FieldError.
func message(err error) string {
	if te, ok := errors.AsType[*yaml.TypeError](err); ok && len(te.Errors) > 0 {
		msg := te.Errors[0]
		if _, rest, ok := strings.Cut(msg, ": "); ok && strings.HasPrefix(msg, "line ") {
			msg = rest
		}
		return msg
	}
	return err.Error()
}
