package utility

import (
	"golang.org/x/crypto/sha3"
)

// HashFunction128 is a SHA-3-256 hash function truncated to 128 bits.
func HashFunction128(data []byte) []byte {
	hash := sha3.Sum256(data)
	return hash[:16] // Truncate to 128 bits
}
