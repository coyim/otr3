package otr3

import (
	"reflect"
	"testing"
)

func assertDeepEquals(t *testing.T, left, right interface{}) {
	if !reflect.DeepEqual(left, right) {
		t.Errorf("Expected %v to equal %v", left, right)
	}
}
