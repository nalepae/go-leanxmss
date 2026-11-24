package leanxmss

import "encoding/binary"

// Four one-time public leaves at once, through keccakF1600x4.
//
// The leaves of a tree are independent, and every leaf hashes the same sequence of
// inputs: its v/2 secret pairs, its v chains of chainLen - 1 steps, then its leaf
// hash. Four consecutive leaves go through that sequence together, one state per
// leaf. Every input is a whole number of lanes, so the batch builds the inputs as
// lanes directly, with no hashing API or byte encoding.

const (
	rateLanes      = keccakRate / 8                          // Lanes of a Keccak-256 block.
	oneBlockLanes  = (publicParamLen + addressLen + 32) / 8  // Lanes of a secret pair's or a chain step's input: P, A and 32 bytes.
	leafInputLanes = (publicParamLen + addressLen + v*n) / 8 // Lanes of a leaf hash's input: P, A and the v chain ends.
	addressLane    = publicParamLen / 8                      // Lane of the address's first 8 bytes, the others being zero.
	payloadLane    = (publicParamLen + addressLen) / 8       // First lane after P and A.
	keccakPadFirst = 0x01                                    // Keccak's padding, XORed into the byte after the input.
	keccakPadLast  = 0x80 << 56                              // Keccak's padding, XORed into the last byte of the block.
)

// The inputs are whole lanes, the address is two lanes, and a secret pair's or a
// chain step's input fits in one block.
var (
	_ = [1]int{}[(publicParamLen+addressLen+32)%8]
	_ = [1]int{}[(publicParamLen+addressLen+v*n)%8]
	_ = [1]int{}[addressLen-16]
	_ = [1]int{}[oneBlockLanes/rateLanes]
)

// leafBatch holds the state of four leaves computed together. It is not safe for
// concurrent use: each goroutine uses its own.
type leafBatch struct {
	pp     [2]uint64                  // The public parameter, as lanes.
	st     [100]uint64                // The four Keccak states, interleaved: st[4i+j] is lane i of leaf j's.
	input  [4 * leafInputLanes]uint64 // The four inputs being hashed, interleaved as st.
	chains [v][8]uint64               // chains[i][j] and chains[i][4+j]: the two lanes of chain i's value for leaf j.
}

// addressLaneOf returns the first 8 bytes of tw's address, as putAddress writes them,
// as a lane.
func addressLaneOf(tw tweak) uint64 {
	return uint64(tw.lo) | uint64(tw.hi&0xffffff)<<32 | uint64(tw.t|tw.step<<5)<<56
}

// setLane sets lane i of the four inputs to x.
func (b *leafBatch) setLane(i int, x uint64) {
	b.input[4*i], b.input[4*i+1], b.input[4*i+2], b.input[4*i+3] = x, x, x, x
}

// begin sets the four inputs' P and A, the latter tw for the leaves e to e + 3.
func (b *leafBatch) begin(tw tweak, e uint32) {
	b.setLane(0, b.pp[0])
	b.setLane(1, b.pp[1])
	for j := range uint32(4) {
		tw.lo = e + j
		b.input[4*addressLane+int(j)] = addressLaneOf(tw)
	}

	b.setLane(addressLane+1, 0)
}

// hash leaves in b.st the four Keccak-256 states of the first lanes lanes of the four
// inputs, padded: the digests are their lanes 0 to 3.
func (b *leafBatch) hash(lanes int) {
	clear(b.st[:])
	in := b.input[:4*lanes]
	for len(in) >= 4*rateLanes {
		for i, x := range in[:4*rateLanes] {
			b.st[i] ^= x
		}

		keccakF1600x4(&b.st)
		in = in[4*rateLanes:]
	}

	for i, x := range in {
		b.st[i] ^= x
	}

	for j := range 4 {
		b.st[len(in)+j] ^= keccakPadFirst
		b.st[4*(rateLanes-1)+j] ^= keccakPadLast
	}

	keccakF1600x4(&b.st)
}

// leaves writes the leaves e to e + 3 of layer to out, as wotsPublicLeaf computes
// them one by one.
func (b *leafBatch) leaves(pp *publicParam, seed *schemeSeed, layer int, e uint32, out []digest) {
	b.pp = [2]uint64{binary.LittleEndian.Uint64(pp[0:8]), binary.LittleEndian.Uint64(pp[8:16])}

	// The secrets: chains 2t and 2t + 1 start at the two halves of one hash of the seed.
	for t := range v / 2 {
		b.begin(newTweak(tweakPRF, layerHi(layer, uint32(t)), 0), e)
		for i := range 4 {
			b.setLane(payloadLane+i, binary.LittleEndian.Uint64(seed[8*i:]))
		}

		b.hash(oneBlockLanes)
		copy(b.chains[2*t][:], b.st[0:8])
		copy(b.chains[2*t+1][:], b.st[8:16])
	}

	// The chains, each from its start to its end.
	base := newTweak(tweakChain, layerHi(layer, 0), 0)
	for i := range v {
		for step := range chainLen - 1 {
			b.begin(base.withStep(step), e)
			copy(b.input[4*payloadLane:], b.chains[i][:])
			b.setLane(payloadLane+2, uint64(i))
			b.setLane(payloadLane+3, 0)
			b.hash(oneBlockLanes)
			copy(b.chains[i][:], b.st[0:8])
		}
	}

	// The leaf hash, over the chain ends.
	b.begin(newTweak(tweakLeaf, layerHi(layer, 0), 0), e)
	for i := range v {
		copy(b.input[4*(payloadLane+2*i):], b.chains[i][:])
	}

	b.hash(leafInputLanes)
	for j := range out[:4] {
		binary.LittleEndian.PutUint64(out[j][0:8], b.st[j])
		binary.LittleEndian.PutUint64(out[j][8:16], b.st[4+j])
	}
}
