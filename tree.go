package leanxmss

import (
	"fmt"
	"runtime"
	"sync"
)

const (
	layerWidth   = 1 << layerHeight                 // Number of leaves of a layer's tree.
	storedLevel  = layerHeight - 8                  // Level whose nodes a layerTree stores: 2^8 of them, 4 KiB.
	storedNodes  = 1 << (layerHeight - storedLevel) // Number of nodes of the stored level.
	subtreeWidth = 1 << storedLevel                 // Number of leaves under one node of the stored level.
)

// One layer's Merkle tree over 2^16 leaves. Nodes are indexed on the layer, as
// their addresses are: a bottom tree's leaves by their leaf indices.
//
// A tree stores its nodes from level 8 up, as the reference implementation does:
// a path recomputes the 2^8 leaves under the leaf's level-8 node, and the levels
// between. This keeps a tree at 8 KiB instead of 2 MiB, for about 2^8 / 2^16 of
// the cost of building it per path.

// node returns the Merkle parent at level and index j of layer.
func (k *hasher) node(pp *publicParam, layer, level int, j uint32, left, right *digest) digest {
	k.begin(pp, newTweak(tweakNode, layerHi(layer, uint32(level)), j))
	k.write(left[:])
	k.write(right[:])

	return k.truncated()
}

type layerTree struct {
	layer int
	index uint32
	upper [layerHeight - storedLevel + 1][]digest // upper[l] holds the nodes of level storedLevel + l: upper[0] the stored ones, the last the root.
}

// buildLayerTree builds tree index of layer. The leaves are computed on all CPUs.
func buildLayerTree(pp *publicParam, seed *schemeSeed, layer int, index uint32) *layerTree {
	first := index << layerHeight
	leaves := wotsPublicLeaves(pp, seed, layer, first, layerWidth)
	levels := hashLevels(pp, layer, first, 0, storedLevel, leaves)

	return newLayerTree(pp, layer, index, levels[storedLevel])
}

// newLayerTree returns tree index of layer from its stored nodes, which it keeps,
// hashing the levels above them: 2^8 - 1 hashes.
func newLayerTree(pp *publicParam, layer int, index uint32, stored []digest) *layerTree {
	t := &layerTree{layer: layer, index: index}
	copy(t.upper[:], hashLevels(pp, layer, index<<layerHeight, storedLevel, layerHeight, stored))

	return t
}

// wotsPublicLeaves returns the count leaves of layer from leaf first on, computed
// on all CPUs.
func wotsPublicLeaves(pp *publicParam, seed *schemeSeed, layer int, first uint32, count int) []digest {
	leaves := make([]digest, count)
	workers := min(runtime.GOMAXPROCS(0), count)

	var wg sync.WaitGroup
	for i := range workers {
		from, to := i*count/workers, (i+1)*count/workers
		wg.Go(func() {
			k := newHasher()
			for j := from; j < to; j++ {
				leaves[j] = k.wotsPublicLeaf(pp, seed, layer, first+uint32(j))
			}
		})
	}

	wg.Wait()

	return leaves
}

// hashLevels returns levels from to to of layer, from base, the nodes of level
// from over the leaves from first on.
func hashLevels(pp *publicParam, layer int, first uint32, from, to int, base []digest) [][]digest {
	k := newHasher()
	levels := make([][]digest, 0, to-from+1)
	levels = append(levels, base)
	for level := from + 1; level <= to; level++ {
		below := levels[len(levels)-1]
		up := make([]digest, len(below)/2)
		start := first >> level
		for j := range up {
			up[j] = k.node(pp, layer, level, start+uint32(j), &below[2*j], &below[2*j+1])
		}

		levels = append(levels, up)
	}

	return levels
}

func (t *layerTree) root() digest {
	return t.upper[len(t.upper)-1][0]
}

// stored returns the nodes of the stored level.
func (t *layerTree) stored() []digest {
	return t.upper[0]
}

// path returns the authentication path of leaf, or an error if leaf is not in the
// tree. It computes the 2^8 leaves under the leaf's stored node, on all CPUs.
func (t *layerTree) path(pp *publicParam, seed *schemeSeed, leaf uint32) ([layerHeight]digest, error) {
	var path [layerHeight]digest
	k := uint64(leaf) - uint64(t.index)<<layerHeight
	if k>>layerHeight != 0 {
		return path, fmt.Errorf("%w: leaf %d, tree %d", errLeafOutside, leaf, t.index)
	}

	first := leaf &^ (subtreeWidth - 1)
	leaves := wotsPublicLeaves(pp, seed, t.layer, first, subtreeWidth)
	lower := hashLevels(pp, t.layer, first, 0, storedLevel-1, leaves)
	for level := range storedLevel {
		path[level] = lower[level][((leaf-first)>>level)^1]
	}

	for level := storedLevel; level < layerHeight; level++ {
		path[level] = t.upper[level-storedLevel][(k>>level)^1]
	}

	return path, nil
}

// pathRoot returns the root that leaf, at index e on layer, and its authentication
// path reach. Bit z of e says whether the node at level z is the right child.
func (k *hasher) pathRoot(pp *publicParam, layer int, e uint32, leaf digest, path *[layerHeight]digest) digest {
	current := leaf
	for z := range layerHeight {
		sibling := path[z]
		if (e>>z)&1 == 0 {
			current = k.node(pp, layer, z+1, e>>(z+1), &current, &sibling)
			continue
		}

		current = k.node(pp, layer, z+1, e>>(z+1), &sibling, &current)
	}

	return current
}
