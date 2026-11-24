package leanxmss

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// TestKeccakF1600 checks the permutation through Keccak-256 of one-block inputs,
// against golang.org/x/crypto/sha3.
func TestKeccakF1600(t *testing.T) {
	for _, size := range []int{0, 1, 64, 80, keccakRate - 1} {
		input := bytes.Repeat([]byte{0xa5}, size)
		var block [keccakRate]byte
		copy(block[:], input)
		block[size] ^= 0x01
		block[keccakRate-1] ^= 0x80

		var state [25]uint64
		for i := range keccakRate / 8 {
			state[i] = binary.LittleEndian.Uint64(block[8*i:])
		}

		keccakF1600(&state)
		var got [32]byte
		for i := range 4 {
			binary.LittleEndian.PutUint64(got[8*i:], state[i])
		}

		if want := keccak256(input); !bytes.Equal(got[:], want) {
			t.Errorf("Keccak-256 of %d bytes: %x, want %x", size, got, want)
		}
	}
}

// TestKeccakF1600x2 checks the two-state permutation, on every backend this CPU
// can run, against two scalar ones.
func TestKeccakF1600x2(t *testing.T) {
	t.Logf("SHA3 instructions: %v", useSHA3)

	x := uint64(0x0123456789abcdef)
	var a, b [25]uint64
	var s [50]uint64
	for i := range a {
		x = x*6364136223846793005 + 1442695040888963407
		a[i], s[2*i] = x, x
		x = x*6364136223846793005 + 1442695040888963407
		b[i], s[2*i+1] = x, x
	}

	keccakF1600(&a)
	keccakF1600(&b)
	generic := s
	keccakF1600x2Generic(&generic)
	keccakF1600x2(&s)
	for i := range a {
		if s[2*i] != a[i] || s[2*i+1] != b[i] {
			t.Errorf("lane %d: %x %x, want %x %x", i, s[2*i], s[2*i+1], a[i], b[i])
		}

		if generic[2*i] != a[i] || generic[2*i+1] != b[i] {
			t.Errorf("generic lane %d: %x %x, want %x %x", i, generic[2*i], generic[2*i+1], a[i], b[i])
		}
	}
}

// TestKeccakF1600x4 checks the four-state permutation, on every backend this CPU
// can run, against four scalar ones.
func TestKeccakF1600x4(t *testing.T) {
	t.Logf("AVX2 instructions: %v", useAVX2)

	x := uint64(0xfedcba9876543210)
	var states [4][25]uint64
	var s [100]uint64
	for i := range 25 {
		for j := range states {
			x = x*6364136223846793005 + 1442695040888963407
			states[j][i], s[4*i+j] = x, x
		}
	}

	for j := range states {
		keccakF1600(&states[j])
	}

	generic := s
	keccakF1600x4Generic(&generic)
	keccakF1600x4(&s)
	for i := range 25 {
		for j := range states {
			if s[4*i+j] != states[j][i] {
				t.Errorf("lane %d of state %d: %x, want %x", i, j, s[4*i+j], states[j][i])
			}

			if generic[4*i+j] != states[j][i] {
				t.Errorf("generic lane %d of state %d: %x, want %x", i, j, generic[4*i+j], states[j][i])
			}
		}
	}
}

// TestLeastTrialBackends checks that the randomizer search finds the same trial
// with the SHA3 or AVX2 instructions and without them, and that it is the least: no
// trial below it hashes, the slow way, to a codeword.
func TestLeastTrialBackends(t *testing.T) {
	var pp publicParam
	for i := range pp {
		pp[i] = byte(i)
	}

	message := testMessage()
	base := u128{lo: ^uint64(0) - 1000, hi: 5} // the low half carries during the search
	savedSHA3, savedAVX2 := useSHA3, useAVX2
	defer func() { useSHA3, useAVX2 = savedSHA3, savedAVX2 }()

	var found []uint64
	for _, accelerated := range []bool{true, false} {
		useSHA3, useAVX2 = savedSHA3 && accelerated, savedAVX2 && accelerated
		c, ok := leastTrial(&pp, 0, 9, message[:], base)
		if !ok {
			t.Fatal("no trial found")
		}

		found = append(found, c)
	}

	if found[0] != found[1] {
		t.Fatalf("trial %d with SHA3 %v and AVX2 %v, %d without", found[0], savedSHA3, savedAVX2, found[1])
	}

	k := newHasher()
	c := found[0]
	r := addTrial(base, c)
	d := k.messageDigest(&pp, 0, 9, &r, message[:])
	if _, ok := codeword(&d); !ok {
		t.Fatalf("trial %d is not a codeword", c)
	}

	if testing.Short() {
		return
	}

	for below := range c {
		r := addTrial(base, below)
		d := k.messageDigest(&pp, 0, 9, &r, message[:])
		if _, ok := codeword(&d); ok {
			t.Fatalf("trial %d below %d is a codeword", below, c)
		}
	}
}

// TestKeccakF1600x4Head checks the head permutation, on every backend this CPU can
// run, against the full four-state one: same lanes 0 and 1, input unchanged.
func TestKeccakF1600x4Head(t *testing.T) {
	x := uint64(0x0f1e2d3c4b5a6978)
	var s [100]uint64
	for i := range s {
		x = x*6364136223846793005 + 1442695040888963407
		s[i] = x
	}

	input := s
	full := s
	keccakF1600x4Generic(&full)

	var out, generic [8]uint64
	keccakF1600x4Head(&s, &out)
	keccakF1600x4HeadGeneric(&s, &generic)
	if s != input {
		t.Error("the input changed")
	}

	for i := range out {
		if out[i] != full[i] {
			t.Errorf("word %d: %x, want %x", i, out[i], full[i])
		}

		if generic[i] != full[i] {
			t.Errorf("generic word %d: %x, want %x", i, generic[i], full[i])
		}
	}
}

// TestLeafBatch checks four leaves computed together against leaves computed one by
// one, on both layers, from a leaf index that is not a multiple of 4.
func TestLeafBatch(t *testing.T) {
	var pp publicParam
	var seed schemeSeed
	for i := range pp {
		pp[i] = byte(3 * i)
	}

	for i := range seed {
		seed[i] = byte(7*i + 1)
	}

	k := newHasher()
	var b leafBatch
	for layer := range 2 {
		const e = 4097
		got := make([]digest, 4)
		b.leaves(&pp, &seed, layer, e, got)
		for j := range uint32(4) {
			if want := k.wotsPublicLeaf(&pp, &seed, layer, e+j); got[j] != want {
				t.Errorf("layer %d, leaf %d: %x, want %x", layer, e+j, got[j], want)
			}
		}
	}
}

// TestWotsPublicLeavesBackends checks that the leaves of a tree are the same with
// AVX2 and without it, for a count that leaves some goroutines a remainder.
func TestWotsPublicLeavesBackends(t *testing.T) {
	var pp publicParam
	var seed schemeSeed
	pp[0], seed[0] = 1, 2

	saved := useAVX2
	defer func() { useAVX2 = saved }()

	useAVX2 = saved
	accelerated := wotsPublicLeaves(&pp, &seed, 0, 1000, 37)
	useAVX2 = false
	scalar := wotsPublicLeaves(&pp, &seed, 0, 1000, 37)
	for i := range scalar {
		if accelerated[i] != scalar[i] {
			t.Errorf("leaf %d: %x with AVX2 %v, %x without", 1000+i, accelerated[i], saved, scalar[i])
		}
	}
}
