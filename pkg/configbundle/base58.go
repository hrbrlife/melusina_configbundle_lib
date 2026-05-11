package configbundle

import (
	"errors"
	"fmt"
)

// Base58Alphabet is the Solana / Bitcoin Base58 alphabet — same as
// the one popaye's pkg/solana, the fineract-sidecar Go side, and
// the Java Gate 2 use. Drift on this constant breaks the entire
// constellation's signature pipeline.
const Base58Alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

// EncodeBase58 returns the Base58 encoding of input.
func EncodeBase58(input []byte) string {
	if len(input) == 0 {
		return ""
	}
	zeros := 0
	for zeros < len(input) && input[zeros] == 0 {
		zeros++
	}
	val := make([]byte, len(input))
	copy(val, input)
	var encoded []byte
	start := 0
	for start < len(val) {
		if val[start] == 0 {
			start++
			continue
		}
		remainder := 0
		for i := start; i < len(val); i++ {
			acc := remainder*256 + int(val[i])
			val[i] = byte(acc / 58)
			remainder = acc % 58
		}
		encoded = append(encoded, Base58Alphabet[remainder])
	}
	for i := 0; i < zeros; i++ {
		encoded = append(encoded, Base58Alphabet[0])
	}
	for i, j := 0, len(encoded)-1; i < j; i, j = i+1, j-1 {
		encoded[i], encoded[j] = encoded[j], encoded[i]
	}
	return string(encoded)
}

// DecodeBase58 inverts EncodeBase58.
func DecodeBase58(s string) ([]byte, error) {
	if s == "" {
		return nil, errors.New("configbundle: base58 input is empty")
	}
	index := make(map[rune]int, len(Base58Alphabet))
	for i, r := range Base58Alphabet {
		index[r] = i
	}
	result := []byte{0}
	for _, c := range s {
		idx, ok := index[c]
		if !ok {
			return nil, fmt.Errorf("configbundle: invalid base58 character %q", c)
		}
		carry := idx
		for i := len(result) - 1; i >= 0; i-- {
			acc := int(result[i])*58 + carry
			result[i] = byte(acc & 0xff)
			carry = acc >> 8
		}
		for carry > 0 {
			result = append([]byte{byte(carry & 0xff)}, result...)
			carry >>= 8
		}
	}
	zeros := 0
	for zeros < len(s) && s[zeros] == Base58Alphabet[0] {
		zeros++
	}
	for i := 0; i < len(result); i++ {
		if result[i] != 0 {
			return append(make([]byte, zeros), result[i:]...), nil
		}
	}
	return make([]byte, zeros), nil
}
