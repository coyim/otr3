package sexp

import (
	"bufio"
	"io"
)

type sexpValue interface{}

type sexpNil struct{}

type sexpList struct {
	first  sexpValue
	second sexpValue
}

func parse(r io.Reader) sexpValue {
	res, _ := parseItem(bufio.NewReader(r))
	return res
}

func parseItem(r *bufio.Reader) (sexpValue, bool) {
	c, err := r.ReadByte()
	if err != nil {
		return nil, true
	}
	switch c {
	case ' ', '\t', '\n':
		return parseItem(r)
	case '(':
		return parseList(r), false
	case ')':
		return nil, true
	// case '"':
	// 	return parseString(r)
	default:
		r.UnreadByte()
		return parseAtom(r), false
	}
}

func isAtomCharacter(c byte) bool {
	switch c {
	case ' ', '\t', '\n', '(', ')':
		return false
	default:
		return true
	}
}

func parseList(r *bufio.Reader) sexpValue {
	val, end := parseItem(r)
	if end {
		return sexpNil{}
	}
	return sexpList{val, parseList(r)}
}

func parseAtom(r *bufio.Reader) string {
	result := make([]byte, 0, 10)
	c, err := r.ReadByte()
	for err != io.EOF && isAtomCharacter(c) {
		result = append(result, c)
		c, err = r.ReadByte()
	}
	return string(result)
}
