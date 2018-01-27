package gobulb

import "encoding/binary"

// EncryptWithHeader applies an autokey cipher to the message
// prefixed with the message length as an unciphered 4-byte integer.
func EncryptWithHeader(data []byte) []byte {
	size := len(data)
	result := make([]byte, size+4)
	binary.BigEndian.PutUint32(result, uint32(size))
	copy(result[4:], Encrypt(data))
	return result
}

// Encrypt applies a XOR autokey cipher to the message.
func Encrypt(data []byte) []byte {
	result := make([]byte, len(data))
	key := byte(0xAB)
	for i := 0; i < len(data); i++ {
		result[i] = data[i] ^ key
		key = result[i]
	}
	return result
}

// DecryptWithHeader reverses the autokey cipher applied to the message
// taking into account the unciphered 4-byte length header.
func DecryptWithHeader(data []byte) []byte {
	return Decrypt(data[4:])
}

// Decrypt reverses the autokey cipher applied to the message.
func Decrypt(data []byte) []byte {
	result := make([]byte, len(data))
	key := byte(0xAB)
	for i := 0; i < len(data); i++ {
		result[i] = data[i] ^ key
		key = data[i]
	}
	return result
}
