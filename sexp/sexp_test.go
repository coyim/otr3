package sexp

import (
	"bytes"
	"testing"
)

func Test_parse_willParseAnAtom(t *testing.T) {
	result := Parse(bytes.NewBuffer([]byte("hello")))
	assertDeepEquals(t, result, atom{"hello"})
}

func Test_parse_willParseAnEmptyList(t *testing.T) {
	result := Parse(bytes.NewBuffer([]byte("()")))
	assertDeepEquals(t, result, snil{})
}

func Test_parse_willParseAListWithAnAtom(t *testing.T) {
	result := Parse(bytes.NewBuffer([]byte("(an-atom)")))
	assertDeepEquals(t, result, cons{atom{"an-atom"}, snil{}})
}

func Test_parse_willParseAListWithTwoAtoms(t *testing.T) {
	result := Parse(bytes.NewBuffer([]byte("(an-atom another-atom)")))
	assertDeepEquals(t, result, cons{atom{"an-atom"}, cons{atom{"another-atom"}, snil{}}})
}

func Test_parse_willParseAListWithNestedLists(t *testing.T) {
	result := Parse(bytes.NewBuffer([]byte("(an-atom (another-atom))")))
	assertDeepEquals(t, result, cons{atom{"an-atom"}, cons{cons{atom{"another-atom"}, snil{}}, snil{}}})
}
