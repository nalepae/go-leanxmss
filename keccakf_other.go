//go:build (!arm64 && !amd64) || purego

package leanxmss

var (
	// useSHA3 is false: there is no assembly for this architecture, or purego is set.
	useSHA3 = false

	// useAVX2 is false: there is no assembly for this architecture, or purego is set.
	useAVX2 = false
)

// keccakF1600x2 is Keccak-f[1600] of two states at once, interleaved: s[2i] and
// s[2i+1] are lane i of the first and of the second state.
func keccakF1600x2(s *[50]uint64) {
	keccakF1600x2Generic(s)
}

// keccakF1600x4 is Keccak-f[1600] of four states at once, interleaved: s[4i+j] is
// lane i of state j.
func keccakF1600x4(s *[100]uint64) {
	keccakF1600x4Generic(s)
}
