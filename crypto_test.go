package gobulb

import (
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/assert"
)

var plaintextMessage = []byte(`{"system":{"get_sysinfo":{}}}`)

var encryptedMessage = []byte{
	0xd0, 0xf2, 0x81, 0xf8, 0x8b, 0xff, 0x9a, 0xf7, 0xd5, 0xef,
	0x94, 0xb6, 0xd1, 0xb4, 0xc0, 0x9f, 0xec, 0x95, 0xe6, 0x8f,
	0xe1, 0x87, 0xe8, 0xca, 0xf0, 0x8b, 0xf6, 0x8b, 0xf6,
}

func TestEncrypt(t *testing.T) {
	result := Encrypt(plaintextMessage)
	assert.Equal(t, encryptedMessage, result)
}

func TestEncryptWithHeader(t *testing.T) {
	result := EncryptWithHeader(plaintextMessage)

	expected := make([]byte, len(encryptedMessage)+4)
	binary.BigEndian.PutUint32(expected, uint32(len(plaintextMessage)))
	copy(expected[4:], encryptedMessage)

	assert.Equal(t, expected, result)
}

func TestDecrypt(t *testing.T) {
	result := Decrypt(encryptedMessage)
	assert.Equal(t, plaintextMessage, result)
}

func TestDecryptWithHeader(t *testing.T) {
	message := make([]byte, len(encryptedMessage)+4)
	binary.BigEndian.PutUint32(message, uint32(len(encryptedMessage)))
	copy(message[4:], encryptedMessage)

	result := DecryptWithHeader(message)
	assert.Equal(t, plaintextMessage, result)
}
