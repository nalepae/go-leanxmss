// Package leanxmss implements leanXMSS, the post-quantum hash-based signature
// scheme of Ethereum's PQ consensus specification, over Keccak-256.
//
// leanXMSS is two layers of XMSS trees of height 16 over WOTS+C one-time keys.
// Each leaf of the top tree signs the root of one bottom tree, whose 2^16 leaves
// sign messages, so a key signs at 2^32 leaf indices. A private key is a 32-byte
// seed, a public key is 32 bytes, and a signature is 2,404 bytes.
//
// This package is a port of the reference implementation, the lean_xmss crate of
// https://github.com/leanEthereum/leanVM at commit
// f7ba4999ae523b94c8d0969b32762c3effea4cbd, specified by doc/lean_xmss there.
// Its tests check every output byte for byte against the test vectors of EthLib,
// the Lean specification of the scheme (https://github.com/ethereum/EthLib).
//
// # Leaf indices
//
// leanXMSS is a stateful scheme: a key must never sign two different messages at
// the same leaf index, or forgeries become possible. This package does not keep
// track of used leaf indices. Choosing a fresh one for each message is the
// caller's duty. Signing is deterministic: signing the same message at the same
// leaf index again gives the same signature, which is safe.
//
// # Cost
//
// [NewKeyFromSeed] builds the whole top tree, about 14 million Keccak-256
// permutations. The first signature in a bottom tree builds that tree, at the same
// cost. Both are spread over all CPUs. A [PrivateKey] caches the 8 bottom trees
// it used last; [PrivateKey.Prepare] builds one
// ahead of time. Verification costs 186 permutations.
//
// A tree keeps its 2^8 nodes of level 8 and the levels above, 8 KiB:
// a signature recomputes the 2^8 leaves under its leaf's level-8 node, about
// 52,000 permutations.
//
// # Tree cache
//
// [PrivateKey.TreeCache] encodes the trees of a key, in the format of the
// reference implementation's cache_to_bytes: 4,096 bytes, plus 5,300 per cached
// bottom tree. [NewKeyFromCache] loads them back in well under a millisecond,
// checked against a trusted public key, instead of building them.
// [SeedPublicParam] gives the public parameter of a seed's key for two hashes, to
// find its public key among known ones.
//
// Signing is mostly the search for a randomizer, about a million permutations.
// On arm64 CPUs with the Armv8.2 SHA3 instructions, it permutes two Keccak states
// at once with them, and on amd64 CPUs with AVX2, four, unless built with the
// purego tag. With AVX2, building a tree also computes its leaves four at a time.
package leanxmss
