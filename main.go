package main

import (
	"fmt"

	"github.com/kelvinator07/merkle-tree/merkle"
	"github.com/kelvinator07/merkle-tree/utility"
)

func main() {
	data := [][]byte{
		[]byte("data1"),
		[]byte("data2"),
		[]byte("data3"),
		[]byte("data4"),
	}

	// Create new merkle tree
	tree := merkle.NewMerkleTree(data)
	fmt.Printf("Merkle Root Hash: %x\n", tree.Root.Hash)

	// Generate merkle proof for leaf at index 0
	leafIndex := 0
	proof, err := tree.GenerateMerkleProof(leafIndex)
	if err != nil {
		fmt.Println("Error generating proof:", err)
		return
	}

	fmt.Printf("Merkle proof for leaf %x: \n", leafIndex)
	for _, p := range proof {
		fmt.Printf("%x\n", p)
	}

	leafHash := utility.HashFunction128(data[leafIndex])
	isValid := merkle.VerifyMerkleProof(tree.Root.Hash, leafHash, proof)
	fmt.Printf("Proof valid: %v\n", isValid)

	// Insert a new leaf
	tree.InsertLeaf([]byte("data5"))
	fmt.Printf("New Merkle Root Hash after insertion: %x\n", tree.Root.Hash)

	// Update an existing leaf at index 1
	updateLeaf := 1
	err = tree.UpdateLeaf(updateLeaf, []byte("updated_data2"))
	if err != nil {
		fmt.Println("Error updating leaf:", err)
		return
	}
	fmt.Printf("New Merkle Root Hash after updating leaf 2: %x\n", tree.Root.Hash)
}
