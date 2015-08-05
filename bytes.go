package otr3

type messageWithHeader []byte
type encodedMessage []byte
type messageFragment []byte
type FragmentedMessage []messageFragment

func (m FragmentedMessage) Bytes() [][]byte {
	ret := make([][]byte, len(m))

	for i, f := range m {
		ret[i] = make([]byte, len(f))
		copy(ret[i], []byte(f))
	}

	return ret
}
