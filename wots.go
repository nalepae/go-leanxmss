package leanxmss

import (
	"encoding/binary"
	"fmt"
	"math"
	"math/bits"
	"runtime"
	"sync"
	"sync/atomic"
)

// The one-time signature, WOTS+C: v hash chains of 2^w - 1 steps, and a target-sum
// code in place of the Winternitz checksum.
//
// A layer's message digest is Th(P, A, M | R), read as digits of w bits, little
// endian. It is a codeword when its last zeroDigits digits are zero, so those have
// no chain, and the other v sum to targetSum. The signer grinds the randomizer R
// until it is.

const (
	lowBits    = 0x5555555555555555 // Low bit of every 2-bit digit set.
	notFound   = math.MaxUint64     // Marks a search range without a codeword. Trials are below 2^32.
	trialChunk = 1 << 12            // Number of consecutive trials one goroutine scans at a time.
)

// randomizer is the value a layer's message digest is computed under.
type randomizer [randomizerLen]byte

// layerIndex returns the index of leafIndex's one-time key on layer: the leaf index
// itself at the bottom, the bottom tree's index at the top.
func layerIndex(leafIndex uint32, layer int) uint32 {
	return uint32(uint64(leafIndex) >> (layer * layerHeight))
}

// wotsSecrets returns the starts of the v chains of key e on layer. One hash of the
// seed gives two of them: chains 2t and 2t + 1 are its two halves.
func (k *hasher) wotsSecrets(pp *publicParam, seed *schemeSeed, layer int, e uint32) [v]digest {
	var secrets [v]digest
	for t := range v / 2 {
		secrets[2*t], secrets[2*t+1] = k.thPair(pp, newTweak(tweakPRF, layerHi(layer, uint32(t)), e), seed)
	}

	return secrets
}

// chain walks steps steps of chain i of key e on layer from position start. A
// step's address carries the position it leaves, and the chain index follows the
// value, as a 16-byte little-endian integer. Callers keep start + steps below
// chainLen: start is a w-bit digit, and steps at most chainLen - 1 - start.
func (k *hasher) chain(pp *publicParam, layer int, e uint32, i, start, steps int, value digest) digest {
	var index [16]byte
	binary.LittleEndian.PutUint64(index[:8], uint64(i))
	base := newTweak(tweakChain, layerHi(layer, 0), e)

	for from := start; from < start+steps; from++ {
		k.begin(pp, base.withStep(from))
		k.write(value[:])
		k.write(index[:])
		value = k.truncated()
	}

	return value
}

// wotsLeafHash returns the Merkle leaf of a one-time key: Th over its v chain ends.
func (k *hasher) wotsLeafHash(pp *publicParam, layer int, e uint32, ends *[v]digest) digest {
	k.begin(pp, newTweak(tweakLeaf, layerHi(layer, 0), e))
	for i := range ends {
		k.write(ends[i][:])
	}

	return k.truncated()
}

// messageDigest returns the digest key e on layer signs: Th(P, A, M | R), M the
// message at the bottom and the bottom root at the top.
func (k *hasher) messageDigest(pp *publicParam, layer int, e uint32, r *randomizer, message []byte) digest {
	k.begin(pp, newTweak(tweakMsg, layerHi(layer, 0), e))
	k.write(message)
	k.write(r[:])

	return k.truncated()
}

// isCodeword reports whether the 128-bit little-endian digest lo | hi << 64 is a
// codeword: its digits past the v-th are zero, and, a 2-bit digit being its low bit
// plus twice its high bit, the others sum to targetSum.
func isCodeword(lo, hi uint64) bool {
	if hi>>(w*v-64) != 0 {
		return false
	}

	sum := bits.OnesCount64(lo&lowBits) + bits.OnesCount64(hi&lowBits) +
		2*(bits.OnesCount64(lo&^lowBits)+bits.OnesCount64(hi&^lowBits))

	return sum == targetSum
}

// codeword returns the digest's first v digits, if it is a codeword.
func codeword(d *digest) ([v]uint8, bool) {
	var x [v]uint8
	lo := binary.LittleEndian.Uint64(d[0:8])
	hi := binary.LittleEndian.Uint64(d[8:16])
	if !isCodeword(lo, hi) {
		return x, false
	}

	for i := range v {
		bit := w * i // w divides 8, so no digit spans two bytes.
		x[i] = d[bit/8] >> (bit % 8) & (chainLen - 1)
	}

	return x, true
}

// u128 is a 128-bit unsigned integer.
type u128 struct {
	lo, hi uint64
}

// addTrial returns base + c, modulo 2^128, as 16 little-endian bytes.
func addTrial(base u128, c uint64) randomizer {
	lo, carry := bits.Add64(base.lo, c, 0)
	hi, _ := bits.Add64(base.hi, 0, carry)

	var r randomizer
	binary.LittleEndian.PutUint64(r[0:8], lo)
	binary.LittleEndian.PutUint64(r[8:16], hi)

	return r
}

// trialSearch is the search for the least admissible trial of one digest.
//
// A trial's hash input P | A | M | R is one Keccak-256 block, R at a lane
// boundary, so the search pads it once, into a state with R zero: a trial XORs its
// R into two lanes, and costs one permutation.
type trialSearch struct {
	state [25]uint64 // The padded block of P | A | M | 0, before the permutation.
	at    int        // The lane R starts at.
	base  u128

	nextChunk atomic.Uint64
	best      atomic.Uint64
}

const keccakRate = 136 // Keccak-256's block, in bytes.

// The trials' inputs are one block, and the randomizer starts a lane.
var (
	_ = [1]int{}[(publicParamLen+addressLen+messageSize+randomizerLen)/keccakRate]
	_ = [1]int{}[(publicParamLen+addressLen+messageSize)%8]
	_ = [1]int{}[(publicParamLen+addressLen+n)%8]
	_ = [1]int{}[trialChunk%4]          // trials come in pairs, or in fours with AVX2
	_ = [1]int{}[maxRandomizerTrials%4] // so do the chunks' ends
)

func newTrialSearch(pp *publicParam, layer int, e uint32, message []byte, base u128) *trialSearch {
	var block [keccakRate]byte
	copy(block[:], pp[:])
	putAddress((*[addressLen]byte)(block[publicParamLen:]), newTweak(tweakMsg, layerHi(layer, 0), e))
	at := publicParamLen + addressLen + copy(block[publicParamLen+addressLen:], message)
	block[at+randomizerLen] = 0x01
	block[keccakRate-1] |= 0x80

	s := &trialSearch{at: at / 8, base: base}
	for i := range keccakRate / 8 {
		s.state[i] = binary.LittleEndian.Uint64(block[8*i:])
	}

	s.best.Store(notFound)
	return s
}

// leastTrial returns the least c below maxRandomizerTrials whose randomizer
// base + c makes key e's digest of message on layer a codeword: the least, which
// keeps one key to one codeword. The search is spread over all CPUs: each
// goroutine scans chunks of consecutive trials in increasing order, and stops at
// the first chunk past a codeword found. Every chunk below the least codeword
// is scanned.
func leastTrial(pp *publicParam, layer int, e uint32, message []byte, base u128) (uint64, bool) {
	s := newTrialSearch(pp, layer, e, message, base)

	var wg sync.WaitGroup
	for range runtime.GOMAXPROCS(0) {
		wg.Go(s.work)
	}

	wg.Wait()

	c := s.best.Load()
	return c, c != notFound
}

func (s *trialSearch) work() {
	for {
		from := (s.nextChunk.Add(1) - 1) * trialChunk
		if from >= maxRandomizerTrials || from >= s.best.Load() {
			return
		}

		c := s.firstTrial(from, min(from+trialChunk, maxRandomizerTrials))
		if c == notFound {
			continue
		}

		for best := s.best.Load(); c < best && !s.best.CompareAndSwap(best, c); best = s.best.Load() {
		}
	}
}

// firstTrial returns the least c in [from, to) whose randomizer base + c makes the
// digest a codeword, or notFound. from and to are multiples of 4.
func (s *trialSearch) firstTrial(from, to uint64) uint64 {
	if useAVX2 {
		return s.firstTrial4(from, to)
	}

	return s.firstTrial2(from, to)
}

// firstTrial2 is firstTrial, trying two trials per permutation call.
func (s *trialSearch) firstTrial2(from, to uint64) uint64 {
	var st [50]uint64
	at := s.at
	for c := from; c < to; c += 2 {
		for i, lane := range s.state {
			st[2*i], st[2*i+1] = lane, lane
		}

		lo0, carry0 := bits.Add64(s.base.lo, c, 0)
		lo1, carry1 := bits.Add64(s.base.lo, c+1, 0)
		st[2*at] ^= lo0
		st[2*at+1] ^= lo1
		st[2*at+2] ^= s.base.hi + carry0
		st[2*at+3] ^= s.base.hi + carry1
		keccakF1600x2(&st)

		// The digest's first 16 bytes are lanes 0 and 1, little endian.
		if isCodeword(st[0], st[2]) {
			return c
		}

		if isCodeword(st[1], st[3]) {
			return c + 1
		}
	}

	return notFound
}

// firstTrial4 is firstTrial, trying four trials per permutation call. The state
// is filled once, and each call only writes the randomizers: the template's
// randomizer lanes are zero, and the permutation leaves its input unchanged.
func (s *trialSearch) firstTrial4(from, to uint64) uint64 {
	var st [100]uint64
	var out [8]uint64
	for i, lane := range s.state {
		st[4*i], st[4*i+1], st[4*i+2], st[4*i+3] = lane, lane, lane, lane
	}

	at := 4 * s.at
	for c := from; c < to; c += 4 {
		for j := range 4 {
			lo, carry := bits.Add64(s.base.lo, c+uint64(j), 0)
			st[at+j] = lo
			st[at+4+j] = s.base.hi + carry
		}

		keccakF1600x4Head(&st, &out)

		// The digests' first 16 bytes are lanes 0 and 1, little endian.
		for j := range uint64(4) {
			if isCodeword(out[j], out[4+j]) {
				return c + j
			}
		}
	}

	return notFound
}

// wotsSign signs message with key e on layer: the randomizer of the least
// admissible trial R0 + c, R0 a hash of the seed and the message, and the chain
// value each digit opens. It is deterministic in its inputs. It returns an error
// if none of the trials gives a codeword.
func wotsSign(pp *publicParam, seed *schemeSeed, layer int, e uint32, message []byte) (randomizer, [v]digest, error) {
	k := newHasher()
	k.begin(pp, newTweak(tweakRandomizer, layerHi(layer, 0), e))
	k.write(seed[:])
	k.write(message)
	out := k.sum()
	base := u128{lo: binary.LittleEndian.Uint64(out[0:8]), hi: binary.LittleEndian.Uint64(out[8:16])}

	c, ok := leastTrial(pp, layer, e, message, base)
	if !ok {
		return randomizer{}, [v]digest{}, fmt.Errorf("%w: layer %d, key %d, %d trials", errNoCodeword, layer, e, uint64(maxRandomizerTrials))
	}

	r := addTrial(base, c)
	d := k.messageDigest(pp, layer, e, &r, message)
	x, ok := codeword(&d)
	if !ok {
		return randomizer{}, [v]digest{}, fmt.Errorf("%w: layer %d, key %d, trial %d", errNoCodeword, layer, e, c)
	}

	secrets := k.wotsSecrets(pp, seed, layer, e)
	var values [v]digest
	for i := range v {
		values[i] = k.chain(pp, layer, e, i, 0, int(x[i]), secrets[i])
	}

	return r, values, nil
}

// wotsLeaf returns the leaf a claimed signature recovers, or false if its digest
// is not a codeword.
func (k *hasher) wotsLeaf(pp *publicParam, layer int, e uint32, message []byte, r *randomizer, values *[v]digest) (digest, bool) {
	d := k.messageDigest(pp, layer, e, r, message)
	x, ok := codeword(&d)
	if !ok {
		return digest{}, false
	}

	var ends [v]digest
	for i := range v {
		start := int(x[i])
		ends[i] = k.chain(pp, layer, e, i, start, chainLen-1-start, values[i])
	}

	return k.wotsLeafHash(pp, layer, e, &ends), true
}

// wotsPublicLeaf returns the leaf of key e on layer, from the seed.
func (k *hasher) wotsPublicLeaf(pp *publicParam, seed *schemeSeed, layer int, e uint32) digest {
	secrets := k.wotsSecrets(pp, seed, layer, e)
	var ends [v]digest
	for i := range v {
		ends[i] = k.chain(pp, layer, e, i, 0, chainLen-1, secrets[i])
	}

	return k.wotsLeafHash(pp, layer, e, &ends)
}
