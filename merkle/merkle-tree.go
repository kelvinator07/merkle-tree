package merkle

import (
	"encoding/hex"
	"fmt"

	"github.com/kelvinator07/merkle-tree/utility"
)

// MerkleNode represents a node in the Merkle Tree.
type MerkleNode struct {
	Parent *MerkleNode
	Left   *MerkleNode
	Right  *MerkleNode
	Hash   []byte
}

// MerkleTree represents the Merkle Tree.
type MerkleTree struct {
	Root      *MerkleNode
	LeafNodes []*MerkleNode
}

// NewMerkleNode creates a new Merkle node.
func NewMerkleNode(left, right *MerkleNode, hash []byte) *MerkleNode {
	node := &MerkleNode{
		Left:  left,
		Right: right,
		Hash:  hash,
	}
	if left != nil {
		left.Parent = node
	}
	if right != nil {
		right.Parent = node
	}
	return node
}

// buildMerkleTree recursively builds the Merkle tree from leaf nodes.
func buildMerkleTree(nodes []*MerkleNode) *MerkleNode {
	if len(nodes) == 1 {
		return nodes[0]
	}

	var parentNodes []*MerkleNode

	for i := 0; i < len(nodes); i += 2 {
		var left, right *MerkleNode
		left = nodes[i]

		if i+1 < len(nodes) {
			right = nodes[i+1]
		} else {
			right = NewMerkleNode(nil, nil, left.Hash) // Duplicate the last node if odd number of nodes
		}

		combinedHash := append(left.Hash, right.Hash...)
		parentHash := utility.HashFunction128(combinedHash)
		parentNode := NewMerkleNode(left, right, parentHash)
		parentNodes = append(parentNodes, parentNode)
	}

	return buildMerkleTree(parentNodes)
}

// NewMerkleTree creates a new Merkle tree from a list of data.
func NewMerkleTree(data [][]byte) *MerkleTree {
	var leafNodes []*MerkleNode

	for _, datum := range data {
		hash := utility.HashFunction128(datum)
		node := NewMerkleNode(nil, nil, hash)
		leafNodes = append(leafNodes, node)
	}

	tree := &MerkleTree{
		LeafNodes: leafNodes,
	}
	tree.Root = buildMerkleTree(leafNodes)
	return tree
}

// GenerateMerkleProof generates a Merkle proof for the given leaf index.
func (tree *MerkleTree) GenerateMerkleProof(index int) ([][]byte, error) {
	if index < 0 || index >= len(tree.LeafNodes) {
		return nil, fmt.Errorf("index out of bounds")
	}

	var proof [][]byte
	node := tree.LeafNodes[index]

	for node != tree.Root {
		var sibling *MerkleNode

		if node == node.Parent.Left {
			sibling = node.Parent.Right
		} else {
			sibling = node.Parent.Left
		}

		if sibling != nil {
			proof = append(proof, sibling.Hash)
		} else {
			proof = append(proof, node.Hash)
		}

		node = node.Parent
	}

	return proof, nil
}

// VerifyMerkleProof verifies a Merkle proof for the given leaf data and root hash.
func VerifyMerkleProof(rootHash, leafHash []byte, proof [][]byte) bool {
	currentHash := leafHash

	for _, hash := range proof {
		combinedHash := append(currentHash, hash...)
		currentHash = utility.HashFunction128(combinedHash)
	}

	return hex.EncodeToString(currentHash) == hex.EncodeToString(rootHash)
}

// InsertLeaf inserts a new leaf into the Merkle tree.
func (tree *MerkleTree) InsertLeaf(data []byte) {
	hash := utility.HashFunction128(data)
	newNode := NewMerkleNode(nil, nil, hash)
	tree.LeafNodes = append(tree.LeafNodes, newNode)
	tree.Root = buildMerkleTree(tree.LeafNodes)
}

// UpdateLeaf updates an existing leaf in the Merkle tree.
func (tree *MerkleTree) UpdateLeaf(index int, data []byte) error {
	if index < 0 || index >= len(tree.LeafNodes) {
		return fmt.Errorf("index out of bounds")
	}

	hash := utility.HashFunction128(data)
	tree.LeafNodes[index].Hash = hash
	tree.Root = buildMerkleTree(tree.LeafNodes)
	return nil
}
