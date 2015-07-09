package sexp

import (
	"bufio"
	"io"
)

type value interface {
	First() value
	Second() value
	String() string
}

type snil struct{}

type atom struct {
	val string
}

type cons struct {
	first  value
	second value
}

func (l cons) First() value {
	return l.first
}

func (l cons) Second() value {
	return l.second
}

func (l cons) String() string {
	panic("not valid to call String on a list")
}

func (l snil) First() value {
	return l
}

func (l snil) Second() value {
	return l
}

func (l snil) String() string {
	panic("not valid to call String on nil")
}

func (l atom) First() value {
	panic("not valid to call first on an atom")
}

func (l atom) Second() value {
	panic("not valid to call second on an atom")
}

func (l atom) String() string {
	return l.val
}

func Parse(r io.Reader) value {
	res, _ := ParseItem(bufio.NewReader(r))
	return res
}

func ParseItem(r *bufio.Reader) (value, bool) {
	c, err := r.ReadByte()
	if err != nil {
		return nil, true
	}
	switch c {
	case ' ', '\t', '\n':
		return ParseItem(r)
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

func parseList(r *bufio.Reader) value {
	val, end := ParseItem(r)
	if end {
		return snil{}
	}
	return cons{val, parseList(r)}
}

func parseAtom(r *bufio.Reader) atom {
	result := make([]byte, 0, 10)
	c, err := r.ReadByte()
	for err != io.EOF && isAtomCharacter(c) {
		result = append(result, c)
		c, err = r.ReadByte()
	}
	return atom{string(result)}
}
