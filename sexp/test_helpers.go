package sexp

import (
	"reflect"
	"testing"
)

func assertEquals(t *testing.T, actual, expected interface{}) {
	if actual != expected {
		t.Errorf("Expected %v to equal %v", actual, expected)
	}
}

func assertDeepEquals(t *testing.T, actual, expected interface{}) {
	if !reflect.DeepEqual(actual, expected) {
		t.Errorf("Expected %v to equal %v", actual, expected)
	}
}
