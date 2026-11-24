//go:build amd64 && !purego

package leanxmss

import "golang.org/x/sys/cpu"

//go:generate go run gen_keccakf_amd64.go

var (
	// useSHA3 is false: the Armv8.2 SHA3 instructions are arm64's.
	useSHA3 = false

	// useAVX2 says whether the randomizer search permutes four Keccak states at once with
	// the AVX2 instructions.
	useAVX2 = cpu.X86.HasAVX2
)

// keccakF1600x4AVX2 is Keccak-f[1600] of four interleaved states, with AVX2.
//
//go:noescape
func keccakF1600x4AVX2(s *[100]uint64)

// keccakF1600x4HeadAVX2 is keccakF1600x4Head, with AVX2.
//
//go:noescape
func keccakF1600x4HeadAVX2(s *[100]uint64, out *[8]uint64)

// keccakF1600x2 is Keccak-f[1600] of two states at once, interleaved: s[2i] and
// s[2i+1] are lane i of the first and of the second state.
func keccakF1600x2(s *[50]uint64) {
	keccakF1600x2Generic(s)
}

// keccakF1600x4 is Keccak-f[1600] of four states at once, interleaved: s[4i+j] is
// lane i of state j.
func keccakF1600x4(s *[100]uint64) {
	if useAVX2 {
		keccakF1600x4AVX2(s)
		return
	}

	keccakF1600x4Generic(s)
}

// keccakF1600x4Head writes to out lanes 0 and 1 of Keccak-f[1600] of four
// interleaved states, s[4i+j] lane i of state j, leaving s unchanged: out[j] and
// out[4+j] are lanes 0 and 1 of state j.
func keccakF1600x4Head(s *[100]uint64, out *[8]uint64) {
	if useAVX2 {
		keccakF1600x4HeadAVX2(s, out)
		return
	}

	keccakF1600x4HeadGeneric(s, out)
}
