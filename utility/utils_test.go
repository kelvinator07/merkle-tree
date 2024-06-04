package utility_test

import (
	"bytes"
	"testing"

	"github.com/kelvinator07/merkle-tree/utility"
)

func TestHashFunction128(t *testing.T) {
	// Test case 1: Check if the hash length is 16 bytes (128 bits)
	t.Run("HashLength", func(t *testing.T) {
		data := []byte("test data")
		hash := utility.HashFunction128(data)
		if len(hash) != 16 {
			t.Errorf("expected hash length of 16 bytes, got %d bytes", len(hash))
		}
	})

	// Test case 2: Check if different inputs produce different hashes
	t.Run("DifferentInputs", func(t *testing.T) {
		data1 := []byte("test data 1")
		data2 := []byte("test data 2")
		hash1 := utility.HashFunction128(data1)
		hash2 := utility.HashFunction128(data2)
		if bytes.Equal(hash1, hash2) {
			t.Errorf("expected different hashes for different inputs, got identical hashes")
		}
	})

	// Test case 3: Check if the same input produces the same hash
	t.Run("SameInput", func(t *testing.T) {
		data := []byte("consistent data")
		hash1 := utility.HashFunction128(data)
		hash2 := utility.HashFunction128(data)
		if !bytes.Equal(hash1, hash2) {
			t.Errorf("expected identical hashes for the same input, got different hashes")
		}
	})

}
