package leanxmss

import (
	"encoding/binary"
	"fmt"
	"math/bits"
	"runtime"
)

const (
	// VRFTreeDepth is the depth of a VRF tree: it has 2^31 leaves, one for each slot.
	VRFTreeDepth = 31
	// VRFProofLen is the number of hashes of a VRF proof: the leaf, then its path.
	VRFProofLen = VRFTreeDepth + 1
	// VRFStateSize is the length of an encoded [VRFState], in bytes.
	VRFStateSize = leafIndexSize + VRFTreeDepth*vrfHashSize
	// DefaultVRFLeaves is how many leaves devnets fill: enough for 145 days of 12 s slots.
	DefaultVRFLeaves = 1 << 20

	vrfHashSize      = 32
	vrfLeaves        = 1 << VRFTreeDepth
	vrfParallelLevel = 12
)

// VRFKey derives the leaves of a VRF tree, the Keccak-256 Merkle tree whose root a
// validator registers and whose leaf for a slot a block reveals as its RANDAO
// contribution. Leaf i is Keccak-256(seed | i as 8 little-endian bytes) below the
// number of filled leaves and zero from there on.
type VRFKey struct {
	seed   [vrfHashSize]byte
	leaves uint64
	zeros  [VRFTreeDepth][vrfHashSize]byte
	tokens chan struct{}
}

// VRFState is what revealing the leaf of one slot needs besides the seed: the
// leaf's path. It holds nothing secret once the leaf is revealed.
type VRFState struct {
	slot uint32
	path [VRFTreeDepth][vrfHashSize]byte
}

// NewVRFKey returns the key of a seed with its first leaves filled, at most 2^31.
// It builds no tree.
func NewVRFKey(seed [vrfHashSize]byte, leaves uint64) (*VRFKey, error) {
	if leaves > vrfLeaves {
		return nil, fmt.Errorf("%w: %d filled leaves, at most %d", errLeafOutside, leaves, uint64(vrfLeaves))
	}

	k := &VRFKey{seed: seed, leaves: leaves, tokens: make(chan struct{}, runtime.GOMAXPROCS(0))}
	for level := 1; level < VRFTreeDepth; level++ {
		k.zeros[level] = vrfNode(&k.zeros[level-1], &k.zeros[level-1])
	}

	return k, nil
}

// State returns the state at slot, hashing every filled leaf once.
func (k *VRFKey) State(slot uint32) (*VRFState, error) {
	if slot >= vrfLeaves {
		return nil, fmt.Errorf("%w: slot %d of a VRF tree", errLeafOutside, slot)
	}

	s := &VRFState{slot: slot}
	for level := range s.path {
		s.path[level] = k.subtree(level, uint64(slot>>level)^1)
	}

	return s, nil
}

// Advance returns the state at slot. It hashes the filled leaves of the subtree
// below the level where the two slots' paths part, and none of the leaves past
// the filled ones. It may move backwards: revealing a leaf twice gives nothing
// away, unlike signing twice at a leaf of a [PrivateKey].
func (k *VRFKey) Advance(s *VRFState, slot uint32) (*VRFState, error) {
	if slot >= vrfLeaves {
		return nil, fmt.Errorf("%w: slot %d of a VRF tree", errLeafOutside, slot)
	}

	next := *s
	next.slot = slot
	if slot == s.slot {
		return &next, nil
	}

	split := bits.Len32(slot^s.slot) - 1
	next.path[split] = k.fold(s, split)
	for level := range split {
		next.path[level] = k.subtree(level, uint64(slot>>level)^1)
	}

	return &next, nil
}

// Root returns the root s leads to under k's seed: the validator's VRF root.
func (k *VRFKey) Root(s *VRFState) [vrfHashSize]byte {
	return k.fold(s, VRFTreeDepth)
}

// Proof returns the proof of the slot of s: its leaf, then the leaf's path.
func (k *VRFKey) Proof(s *VRFState) [VRFProofLen][vrfHashSize]byte {
	var proof [VRFProofLen][vrfHashSize]byte

	proof[0] = k.leaf(uint64(s.slot))
	copy(proof[1:], s.path[:])

	return proof
}

// Slot returns the slot the state reveals the leaf of.
func (s *VRFState) Slot() uint32 {
	return s.slot
}

// Bytes returns the encoding of s, [VRFStateSize] bytes long.
func (s *VRFState) Bytes() []byte {
	out := make([]byte, 0, VRFStateSize)
	out = binary.LittleEndian.AppendUint32(out, s.slot)
	for i := range s.path {
		out = append(out, s.path[i][:]...)
	}

	return out
}

// VRFStateFromBytes decodes a state encoded by [VRFState.Bytes]. Check it against
// the expected root with [VRFKey.Root] before revealing from it.
func VRFStateFromBytes(b []byte) (*VRFState, error) {
	if len(b) != VRFStateSize {
		return nil, fmt.Errorf("%w: VRF state of %d bytes, want %d", errInvalidLength, len(b), VRFStateSize)
	}

	s := &VRFState{slot: binary.LittleEndian.Uint32(b[:leafIndexSize])}
	if s.slot >= vrfLeaves {
		return nil, fmt.Errorf("%w: slot %d of a VRF tree", errLeafOutside, s.slot)
	}

	for i := range s.path {
		copy(s.path[i][:], b[leafIndexSize+i*vrfHashSize:])
	}

	return s, nil
}

// VerifyVRFProof reports whether proof opens the leaf of slot under root, as
// is_valid_vrf_proof of the consensus specifications does: only the 31 low bits
// of the slot count.
func VerifyVRFProof(root [vrfHashSize]byte, slot uint64, proof *[VRFProofLen][vrfHashSize]byte) bool {
	node := proof[0]
	for level := range VRFTreeDepth {
		if (slot>>level)&1 == 0 {
			node = vrfNode(&node, &proof[level+1])
			continue
		}

		node = vrfNode(&proof[level+1], &node)
	}

	return node == root
}

func (k *VRFKey) leaf(index uint64) [vrfHashSize]byte {
	if index >= k.leaves {
		return k.zeros[0]
	}

	var input [vrfHashSize + 8]byte

	copy(input[:], k.seed[:])
	binary.LittleEndian.PutUint64(input[vrfHashSize:], index)

	return vrfHash(input[:])
}

func (k *VRFKey) fold(s *VRFState, levels int) [vrfHashSize]byte {
	node := k.leaf(uint64(s.slot))
	for level := range levels {
		if (s.slot>>level)&1 == 0 {
			node = vrfNode(&node, &s.path[level])
			continue
		}

		node = vrfNode(&s.path[level], &node)
	}

	return node
}

func (k *VRFKey) subtree(level int, index uint64) [vrfHashSize]byte {
	if index<<level >= k.leaves {
		return k.zeros[level]
	}

	if level == 0 {
		return k.leaf(index)
	}

	var left [vrfHashSize]byte

	done := make(chan struct{})
	spawned := false
	if level >= vrfParallelLevel {
		select {
		case k.tokens <- struct{}{}:
			spawned = true
			go func() {
				left = k.subtree(level-1, 2*index)
				<-k.tokens
				close(done)
			}()
		default:
		}
	}

	if !spawned {
		left = k.subtree(level-1, 2*index)
	}

	right := k.subtree(level-1, 2*index+1)
	if spawned {
		<-done
	}

	return vrfNode(&left, &right)
}

func vrfNode(left, right *[vrfHashSize]byte) [vrfHashSize]byte {
	var input [2 * vrfHashSize]byte

	copy(input[:], left[:])
	copy(input[vrfHashSize:], right[:])

	return vrfHash(input[:])
}

func vrfHash(input []byte) [vrfHashSize]byte {
	var block [keccakRate]byte

	copy(block[:], input)
	block[len(input)] = 0x01
	block[keccakRate-1] |= 0x80

	var state [25]uint64
	for i := range keccakRate / 8 {
		state[i] = binary.LittleEndian.Uint64(block[8*i:])
	}

	keccakF1600(&state)

	var out [vrfHashSize]byte
	for i := range vrfHashSize / 8 {
		binary.LittleEndian.PutUint64(out[8*i:], state[i])
	}

	return out
}
