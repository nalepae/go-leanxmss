package leanxmss

import "math/bits"

// keccakRoundConstants are the round constants of Keccak-f[1600].
var keccakRoundConstants = [24]uint64{
	0x0000000000000001,
	0x0000000000008082,
	0x800000000000808a,
	0x8000000080008000,
	0x000000000000808b,
	0x0000000080000001,
	0x8000000080008081,
	0x8000000000008009,
	0x000000000000008a,
	0x0000000000000088,
	0x0000000080008009,
	0x000000008000000a,
	0x000000008000808b,
	0x800000000000008b,
	0x8000000000008089,
	0x8000000000008003,
	0x8000000000008002,
	0x8000000000000080,
	0x000000000000800a,
	0x800000008000000a,
	0x8000000080008081,
	0x8000000000008080,
	0x0000000080000001,
	0x8000000080008008,
}

// keccakF1600 is the Keccak-f[1600] permutation, each round unrolled over the 25
// lanes, lane x + 5y named a<y><x>.
func keccakF1600(s *[25]uint64) {
	a00, a01, a02, a03, a04, a10, a11, a12, a13, a14, a20, a21, a22, a23, a24, a30, a31, a32, a33, a34, a40, a41, a42, a43, a44 := s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7], s[8], s[9], s[10], s[11], s[12], s[13], s[14], s[15], s[16], s[17], s[18], s[19], s[20], s[21], s[22], s[23], s[24]

	for _, rc := range keccakRoundConstants {
		// θ, then ρ and π into b (lane (x, y) of the result reads b<y><x>), then χ and ι.
		c0 := a00 ^ a10 ^ a20 ^ a30 ^ a40
		c1 := a01 ^ a11 ^ a21 ^ a31 ^ a41
		c2 := a02 ^ a12 ^ a22 ^ a32 ^ a42
		c3 := a03 ^ a13 ^ a23 ^ a33 ^ a43
		c4 := a04 ^ a14 ^ a24 ^ a34 ^ a44
		d0 := c4 ^ bits.RotateLeft64(c1, 1)
		d1 := c0 ^ bits.RotateLeft64(c2, 1)
		d2 := c1 ^ bits.RotateLeft64(c3, 1)
		d3 := c2 ^ bits.RotateLeft64(c4, 1)
		d4 := c3 ^ bits.RotateLeft64(c0, 1)
		b00 := a00 ^ d0
		b20 := bits.RotateLeft64(a01^d1, 1)
		b40 := bits.RotateLeft64(a02^d2, 62)
		b10 := bits.RotateLeft64(a03^d3, 28)
		b30 := bits.RotateLeft64(a04^d4, 27)
		b31 := bits.RotateLeft64(a10^d0, 36)
		b01 := bits.RotateLeft64(a11^d1, 44)
		b21 := bits.RotateLeft64(a12^d2, 6)
		b41 := bits.RotateLeft64(a13^d3, 55)
		b11 := bits.RotateLeft64(a14^d4, 20)
		b12 := bits.RotateLeft64(a20^d0, 3)
		b32 := bits.RotateLeft64(a21^d1, 10)
		b02 := bits.RotateLeft64(a22^d2, 43)
		b22 := bits.RotateLeft64(a23^d3, 25)
		b42 := bits.RotateLeft64(a24^d4, 39)
		b43 := bits.RotateLeft64(a30^d0, 41)
		b13 := bits.RotateLeft64(a31^d1, 45)
		b33 := bits.RotateLeft64(a32^d2, 15)
		b03 := bits.RotateLeft64(a33^d3, 21)
		b23 := bits.RotateLeft64(a34^d4, 8)
		b24 := bits.RotateLeft64(a40^d0, 18)
		b44 := bits.RotateLeft64(a41^d1, 2)
		b14 := bits.RotateLeft64(a42^d2, 61)
		b34 := bits.RotateLeft64(a43^d3, 56)
		b04 := bits.RotateLeft64(a44^d4, 14)
		a00 = b00 ^ (b02 &^ b01) ^ rc
		a01 = b01 ^ (b03 &^ b02)
		a02 = b02 ^ (b04 &^ b03)
		a03 = b03 ^ (b00 &^ b04)
		a04 = b04 ^ (b01 &^ b00)
		a10 = b10 ^ (b12 &^ b11)
		a11 = b11 ^ (b13 &^ b12)
		a12 = b12 ^ (b14 &^ b13)
		a13 = b13 ^ (b10 &^ b14)
		a14 = b14 ^ (b11 &^ b10)
		a20 = b20 ^ (b22 &^ b21)
		a21 = b21 ^ (b23 &^ b22)
		a22 = b22 ^ (b24 &^ b23)
		a23 = b23 ^ (b20 &^ b24)
		a24 = b24 ^ (b21 &^ b20)
		a30 = b30 ^ (b32 &^ b31)
		a31 = b31 ^ (b33 &^ b32)
		a32 = b32 ^ (b34 &^ b33)
		a33 = b33 ^ (b30 &^ b34)
		a34 = b34 ^ (b31 &^ b30)
		a40 = b40 ^ (b42 &^ b41)
		a41 = b41 ^ (b43 &^ b42)
		a42 = b42 ^ (b44 &^ b43)
		a43 = b43 ^ (b40 &^ b44)
		a44 = b44 ^ (b41 &^ b40)
	}

	s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7], s[8], s[9], s[10], s[11], s[12], s[13], s[14], s[15], s[16], s[17], s[18], s[19], s[20], s[21], s[22], s[23], s[24] = a00, a01, a02, a03, a04, a10, a11, a12, a13, a14, a20, a21, a22, a23, a24, a30, a31, a32, a33, a34, a40, a41, a42, a43, a44
}

// keccakF1600x2Generic is Keccak-f[1600] of two interleaved states, as
// keccakF1600x2, by two scalar permutations.
func keccakF1600x2Generic(s *[50]uint64) {
	var a, b [25]uint64
	for i := range a {
		a[i], b[i] = s[2*i], s[2*i+1]
	}

	keccakF1600(&a)
	keccakF1600(&b)
	for i := range a {
		s[2*i], s[2*i+1] = a[i], b[i]
	}
}

// keccakF1600x4Generic is Keccak-f[1600] of four interleaved states, as
// keccakF1600x4, by four scalar permutations.
func keccakF1600x4Generic(s *[100]uint64) {
	var states [4][25]uint64
	for i := range 25 {
		for j := range states {
			states[j][i] = s[4*i+j]
		}
	}

	for j := range states {
		keccakF1600(&states[j])
	}

	for i := range 25 {
		for j := range states {
			s[4*i+j] = states[j][i]
		}
	}
}

// keccakF1600x4HeadGeneric is keccakF1600x4Head, by four scalar permutations.
func keccakF1600x4HeadGeneric(s *[100]uint64, out *[8]uint64) {
	permuted := *s
	keccakF1600x4Generic(&permuted)
	copy(out[:], permuted[:8])
}
