package sexp

import (
	"bytes"
	"testing"
)

func Test_parse_willParseAnAtom(t *testing.T) {
	result := parse(bytes.NewBuffer([]byte("hello")))
	assertDeepEquals(t, result, "hello")
}

func Test_parse_willParseAnEmptyList(t *testing.T) {
	result := parse(bytes.NewBuffer([]byte("()")))
	assertDeepEquals(t, result, sexpNil{})
}

func Test_parse_willParseAListWithAnAtom(t *testing.T) {
	result := parse(bytes.NewBuffer([]byte("(an-atom)")))
	assertDeepEquals(t, result, sexpList{"an-atom", sexpNil{}})
}

func Test_parse_willParseAListWithTwoAtoms(t *testing.T) {
	result := parse(bytes.NewBuffer([]byte("(an-atom another-atom)")))
	assertDeepEquals(t, result, sexpList{"an-atom", sexpList{"another-atom", sexpNil{}}})
}

func Test_parse_willParseAListWithNestedLists(t *testing.T) {
	result := parse(bytes.NewBuffer([]byte("(an-atom (another-atom))")))
	assertDeepEquals(t, result, sexpList{"an-atom", sexpList{sexpList{"another-atom", sexpNil{}}, sexpNil{}}})
}
