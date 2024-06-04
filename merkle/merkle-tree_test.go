package merkle_test

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/kelvinator07/merkle-tree/merkle"
)

func TestNewMerkleTree(t *testing.T) {
	data := [][]byte{
		[]byte("data1"),
		[]byte("data2"),
		[]byte("data3"),
		[]byte("data4"),
	}

	tree := merkle.NewMerkleTree(data)
	if tree.Root == nil {
		t.Error("root should not be nil")
	}

	if len(tree.LeafNodes) != 4 {
		t.Errorf("expected 4 leaf nodes, got %d", len(tree.LeafNodes))
	}
}

func TestGenerateMerkleProof(t *testing.T) {
	data := [][]byte{
		[]byte("data1"),
		[]byte("data2"),
		[]byte("data3"),
		[]byte("data4"),
	}

	tree := merkle.NewMerkleTree(data)

	t.Run("Should generate merkle proof successfully", func(t *testing.T) {
		proof, err := tree.GenerateMerkleProof(0)
		if err != nil {
			t.Errorf("error generating Merkle proof: %v", err)
		}

		if len(proof) == 0 {
			t.Error("proof should not be empty")
		}
	})

	t.Run("Should fail while trying to generate merkle proof", func(t *testing.T) {
		_, err := tree.GenerateMerkleProof(len(data)) // Index equal to length of data
		if err == nil || err.Error() != "index out of bounds" {
			t.Errorf("expected 'index out of bounds' error, got %v", err)
		}

		_, err = tree.GenerateMerkleProof(len(data) + 1) // Index greater than length of data
		if err == nil || err.Error() != "index out of bounds" {
			t.Errorf("expected 'index out of bounds' error, got %v", err)
		}
	})

	// Test case 2: When the sibling is equal to node.Parent.Left
	t.Run("When the sibling is equal to node.Parent.Left", func(t *testing.T) {
		data := [][]byte{
			[]byte("data1"),
			[]byte("data2"),
			[]byte("data3"),
			[]byte("data4"),
		}

		tree := merkle.NewMerkleTree(data)

		// Proof generation for the rightmost leaf (data1)
		expectedProofIndex := 1
		proof, err := tree.GenerateMerkleProof(expectedProofIndex)
		if err != nil {
			t.Errorf("Unexpected error generating proof: %v", err)
		}

		// Verify the first element of the proof is the parent's hash (which is also the sibling's hash)
		if len(proof) == 0 {
			t.Errorf("Empty proof generated")
			return
		}

		expectedHash := tree.LeafNodes[0].Hash

		if !compareByteSlices(proof[0], expectedHash) {
			t.Errorf("Expected proof[0] to be parent's hash (%s), got %s", expectedHash, proof[0])
		}
	})
}

func TestVerifyMerkleProof(t *testing.T) {
	data := [][]byte{
		[]byte("data1"),
		[]byte("data2"),
		[]byte("data3"),
		[]byte("data4"),
	}

	tree := merkle.NewMerkleTree(data)
	proof, err := tree.GenerateMerkleProof(0)
	if err != nil {
		t.Errorf("error generating Merkle proof: %v", err)
	}

	valid := merkle.VerifyMerkleProof(tree.Root.Hash, tree.LeafNodes[0].Hash, proof)
	if !valid {
		t.Error("proof should be valid")
	}
}

func TestInsertLeaf(t *testing.T) {
	data := [][]byte{
		[]byte("data1"),
		[]byte("data2"),
	}

	tree := merkle.NewMerkleTree(data)
	originalRootHash := tree.Root.Hash

	tree.InsertLeaf([]byte("data3"))
	newRootHash := tree.Root.Hash

	if hex.EncodeToString(originalRootHash) == hex.EncodeToString(newRootHash) {
		t.Error("root hash should change after insertion")
	}
}

func TestUpdateLeaf(t *testing.T) {
	data := [][]byte{
		[]byte("data1"),
		[]byte("data2"),
	}

	tree := merkle.NewMerkleTree(data)

	t.Run("should update leaf successfully", func(t *testing.T) {
		originalRootHash := tree.Root.Hash

		err := tree.UpdateLeaf(0, []byte("updated_data1"))
		if err != nil {
			t.Errorf("error updating leaf: %v", err)
		}

		newRootHash := tree.Root.Hash
		if hex.EncodeToString(originalRootHash) == hex.EncodeToString(newRootHash) {
			t.Error("root hash should change after updating leaf")
		}
	})

	t.Run("should fail with index out of bounds when trying to update leaf", func(t *testing.T) {
		err := tree.UpdateLeaf(-1, []byte("updated_data1")) // Index less than zero (0)
		if err == nil || err.Error() != "index out of bounds" {
			t.Errorf("expected 'index out of bounds' error, got %v", err)
		}

		err = tree.UpdateLeaf(len(tree.LeafNodes)+1, []byte("updated_data1")) // Index greater than length of tree
		if err == nil || err.Error() != "index out of bounds" {
			t.Errorf("expected 'index out of bounds' error, got %v", err)
		}
	})
}

// Helper function to compare byte slices
func compareByteSlices(a, b []byte) bool {
	return len(a) == len(b) && bytes.Equal(a, b)
}
