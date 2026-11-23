package leanxmss

import (
	"fmt"
	"runtime"
	"sync"
)

const (
	layerWidth  = 1 << layerHeight                 // Number of leaves of a layer's tree.
	cachedLevel = layerHeight - 8                  // The level of its nodes a tree stores.
	cachedNodes = 1 << (layerHeight - cachedLevel) // Number of nodes a tree stores.
)

// One layer's Merkle tree over 2^16 leaves. Nodes are indexed on the layer, as
// their addresses are: a bottom tree's leaves by their leaf indices.

// node returns the Merkle parent at level and index j of layer.
func (k *hasher) node(pp *publicParam, layer, level int, j uint32, left, right *digest) digest {
	k.begin(pp, newTweak(tweakNode, layerHi(layer, uint32(level)), j))
	k.write(left[:])
	k.write(right[:])

	return k.truncated()
}

// levels returns levels from to to of layer over base, the nodes of level from
// from leaf first on.
func (k *hasher) levels(pp *publicParam, layer int, first uint32, from, to int, base []digest) [][]digest {
	levels := make([][]digest, 0, to-from+1)
	levels = append(levels, base)
	for level := from + 1; level <= to; level++ {
		below := levels[len(levels)-1]
		up := make([]digest, len(below)/2)
		at := first >> level
		for j := range up {
			up[j] = k.node(pp, layer, level, at+uint32(j), &below[2*j], &below[2*j+1])
		}

		levels = append(levels, up)
	}

	return levels
}

// publicLeaves returns the count leaves of layer from first on, computed on all
// CPUs.
func publicLeaves(pp *publicParam, seed *schemeSeed, layer int, first uint32, count int) []digest {
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

// layerTree is tree index of layer: its nodes at cachedLevel. The levels below
// are recomputed from the seed for each path.
type layerTree struct {
	layer int
	index uint32
	nodes []digest
}

// buildLayerTree builds tree index of layer. The leaves are computed on all CPUs.
func buildLayerTree(pp *publicParam, seed *schemeSeed, layer int, index uint32) *layerTree {
	first := index << layerHeight
	leaves := publicLeaves(pp, seed, layer, first, layerWidth)
	levels := newHasher().levels(pp, layer, first, 0, cachedLevel, leaves)

	return &layerTree{layer: layer, index: index, nodes: levels[cachedLevel]}
}

// layerTreeFromBytes returns tree index of layer, from the encoding of its nodes
// at cachedLevel. The caller checks its length.
func layerTreeFromBytes(layer int, index uint32, b []byte) *layerTree {
	nodes := make([]digest, cachedNodes)
	for i := range nodes {
		copy(nodes[i][:], b[i*n:])
	}

	return &layerTree{layer: layer, index: index, nodes: nodes}
}

// appendNodes appends the encoding of the tree's nodes at cachedLevel to out.
func (t *layerTree) appendNodes(out []byte) []byte {
	for i := range t.nodes {
		out = append(out, t.nodes[i][:]...)
	}

	return out
}

// upper returns levels cachedLevel to layerHeight.
func (t *layerTree) upper(k *hasher, pp *publicParam) [][]digest {
	return k.levels(pp, t.layer, t.index<<layerHeight, cachedLevel, layerHeight, t.nodes)
}

func (t *layerTree) root(pp *publicParam) digest {
	return t.upper(newHasher(), pp)[layerHeight-cachedLevel][0]
}

// path returns the authentication path of leaf, or an error if leaf is not in the
// tree. It recomputes the levels below cachedLevel under the leaf's node there.
func (t *layerTree) path(pp *publicParam, seed *schemeSeed, leaf uint32) ([layerHeight]digest, error) {
	var path [layerHeight]digest
	if leaf>>layerHeight != t.index {
		return path, fmt.Errorf("%w: leaf %d, tree %d", errLeafOutside, leaf, t.index)
	}

	k := newHasher()
	first := leaf >> cachedLevel << cachedLevel
	leaves := publicLeaves(pp, seed, t.layer, first, 1<<cachedLevel)
	levels := k.levels(pp, t.layer, first, 0, cachedLevel, leaves)[:cachedLevel]
	levels = append(levels, t.upper(k, pp)...)

	// A level starts at a multiple of its length, hence the modulo.
	for level := range layerHeight {
		path[level] = levels[level][int((leaf>>level)^1)%len(levels[level])]
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
