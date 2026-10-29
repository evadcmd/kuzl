package strictyaml

import (
	"errors"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

// even is a value that validates itself, as a yaml.Unmarshaler.
type even int

func (e *even) UnmarshalYAML(n *yaml.Node) error {
	var i int
	if err := n.Decode(&i); err != nil {
		return err
	}
	if i%2 != 0 {
		return fmt.Errorf("%d is not even", i)
	}
	*e = even(i)
	return nil
}

type limits struct {
	Max  int                `yaml:"max"`
	Tags Optional[[]string] `yaml:"tags"`
}

type model struct {
	Name     string           `yaml:"name"`
	Port     Optional[int]    `yaml:"port"`
	Evens    Optional[[]even] `yaml:"evens"`
	Limits   Optional[limits] `yaml:"limits"`
	Untagged Optional[bool]
	Skipped  string `yaml:"-"`
	hidden   string //nolint:unused // there to be skipped.
}

func wantErrors(t *testing.T, err error, want ...FieldError) {
	t.Helper()
	ve, ok := errors.AsType[*ValidationError](err)
	if !ok {
		t.Fatalf("err = %v, want a *ValidationError", err)
	}
	if !reflect.DeepEqual(ve.Errors, want) {
		t.Errorf("errors =\n%v\nwant\n%v", ve.Errors, want)
	}
}

func TestUnmarshal(t *testing.T) {
	var m model
	err := Unmarshal([]byte(`
name: kuzl
port: 8080
evens: [2, 4]
limits:
  max: 3
Untagged: true
`), &m)
	if err != nil {
		t.Fatal(err)
	}
	want := model{
		Name:     "kuzl",
		Port:     Some(8080),
		Evens:    Some([]even{2, 4}),
		Limits:   Some(limits{Max: 3}),
		Untagged: Some(true),
	}
	if !reflect.DeepEqual(m, want) {
		t.Errorf("got %+v, want %+v", m, want)
	}
	if tags, ok := m.Limits.Or(limits{}).Tags.Get(); ok || tags != nil {
		t.Errorf("limits.tags = %v, %v; want unset", tags, ok)
	}
}

// Left out and null are the same for an Optional; an empty list is set.
func TestOptional(t *testing.T) {
	var m model
	if err := Unmarshal([]byte("name: x\nport: null\nevens: []\n"), &m); err != nil {
		t.Fatal(err)
	}
	if _, ok := m.Port.Get(); ok {
		t.Error("port: null is set, want unset")
	}
	if got := m.Port.Or(80); got != 80 {
		t.Errorf("Or = %d, want the default", got)
	}
	if evens, ok := m.Evens.Get(); !ok || len(evens) != 0 {
		t.Errorf("evens: [] = %v, %v; want set and empty", evens, ok)
	}
}

// Every error is reported, with where it is, in document order.
func TestUnmarshalCollectsAllErrors(t *testing.T) {
	var m model
	err := Unmarshal([]byte(`port: http
evens: [2, 3, 4, 5]
limits:
  tags: tag
  maxx: 1
nam: kuzl
evens: [2]
`), &m)
	wantErrors(t, err,
		FieldError{"port", 1, "cannot unmarshal !!str `http` into int"},
		FieldError{"evens.1", 2, "3 is not even"},
		FieldError{"evens.3", 2, "5 is not even"},
		FieldError{"limits.tags", 4, "should be a list"},
		FieldError{"limits.maxx", 5, "unknown field"},
		FieldError{"limits.max", 4, "field required"},
		FieldError{"nam", 6, "unknown field"},
		FieldError{"evens", 7, "duplicate field"},
		FieldError{"name", 1, "field required"},
	)
	want := "9 validation errors\n  port: cannot unmarshal !!str `http` into int (line 1)\n"
	if !strings.HasPrefix(err.Error(), want) {
		t.Errorf("Error() = %q, want it to start with %q", err.Error(), want)
	}
}

func TestUnmarshalShapes(t *testing.T) {
	var m model
	tests := []struct {
		doc  string
		want []FieldError
	}{
		{"", []FieldError{{"name", 1, "field required"}}},
		{"- a\n", []FieldError{{"", 1, "should be a mapping"}}},
		{"name: null\n", []FieldError{{"name", 1, "should not be null"}}},
		{"name: [a]\n", []FieldError{{"name", 1, "should be a string"}}},
		{"name: x\nlimits: 3\n", []FieldError{{"limits", 2, "should be a mapping"}}},
		{"name: x\nSkipped: y\nhidden: z\n", []FieldError{{"Skipped", 2, "unknown field"}, {"hidden", 3, "unknown field"}}},
	}
	for _, tt := range tests {
		t.Run(tt.doc, func(t *testing.T) {
			wantErrors(t, Unmarshal([]byte(tt.doc), &m), tt.want...)
		})
	}
	if err := Unmarshal([]byte("name: x\nlimits: &l {max: 2}\nevens: [*l]\n"), &m); err == nil {
		t.Error("an alias of the wrong type decoded")
	}
}

// nonEmpty is a list that validates itself as a whole, as a Validator. It
// also refuses 0, which an item that failed to decode leaves behind.
type nonEmpty []even

func (l nonEmpty) Validate() error {
	if len(l) == 0 {
		return errors.New("should not be empty")
	}
	if slices.Contains(l, 0) {
		return errors.New("should not hold 0")
	}
	return nil
}

// A Validator runs once its value has decoded, and only then: its items'
// errors come first and alone.
func TestValidator(t *testing.T) {
	var v struct {
		List Optional[nonEmpty] `yaml:"list"`
	}
	if err := Unmarshal([]byte("list: [2]\n"), &v); err != nil {
		t.Errorf("list: [2] = %v, want ok", err)
	}
	if err := Unmarshal([]byte("{}"), &v); err != nil {
		t.Errorf("no list = %v, want ok", err)
	}
	wantErrors(t, Unmarshal([]byte("\nlist: []\n"), &v), FieldError{"list", 2, "should not be empty"})
	wantErrors(t, Unmarshal([]byte("list: [0]\n"), &v), FieldError{"list", 1, "should not hold 0"})
	wantErrors(t, Unmarshal([]byte("list: [3]\n"), &v), FieldError{"list.0", 1, "3 is not even"})
}

func TestUnmarshalSyntaxError(t *testing.T) {
	var m model
	err := Unmarshal([]byte("name: x\nevens: [2\n"), &m)
	if _, ok := errors.AsType[*ValidationError](err); ok || err == nil || !strings.Contains(err.Error(), "line") {
		t.Errorf("err = %v, want yaml's syntax error with its line", err)
	}
	if err := Unmarshal([]byte("name: x"), m); err == nil {
		t.Error("Unmarshal into a non-pointer = nil, want an error")
	}
}
