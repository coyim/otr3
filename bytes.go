package otr3

type messageWithHeader []byte
type encodedMessage []byte
type messageFragment []byte
type FragmentedMessage []messageFragment

func (m FragmentedMessage) Bytes() [][]byte {
	ret := make([][]byte, len(m))

	//copy because we dont want to hold references to m's fragments
	for i, f := range m {
		ret[i] = make([]byte, len(f))
		copy(ret[i], []byte(f))
	}

	return ret
}
