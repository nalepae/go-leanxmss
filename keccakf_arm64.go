//go:build arm64 && !purego

package leanxmss

import "golang.org/x/sys/cpu"

var (
	// useSHA3 says whether keccakF1600x2 uses the Armv8.2 SHA3 instructions.
	useSHA3 = cpu.ARM64.HasSHA3

	// useAVX2 is false: AVX2 is amd64's.
	useAVX2 = false
)

//go:noescape
func keccakF1600x2NEON(s *[50]uint64)

// keccakF1600x2 is Keccak-f[1600] of two states at once, interleaved: s[2i] and
// s[2i+1] are lane i of the first and of the second state.
func keccakF1600x2(s *[50]uint64) {
	if useSHA3 {
		keccakF1600x2NEON(s)
		return
	}

	keccakF1600x2Generic(s)
}

// keccakF1600x4 is Keccak-f[1600] of four states at once, interleaved: s[4i+j] is
// lane i of state j.
func keccakF1600x4(s *[100]uint64) {
	keccakF1600x4Generic(s)
}
