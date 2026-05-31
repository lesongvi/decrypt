package decrypt

import (
	"crypto/aes"
	"crypto/cipher"
	"errors"
	"fmt"
)

func decryptPayload(encrypted []byte, key []byte) ([]byte, error) {
	if len(encrypted) < 56 {
		return nil, errors.New("invalid encrypted payload: too short")
	}

	iv := encrypted[36:52]
	ciphertext := encrypted[56:]
	if len(ciphertext) == 0 || len(ciphertext)%aes.BlockSize != 0 {
		return nil, errors.New("invalid encrypted payload: ciphertext length is not a multiple of AES block size")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize block cipher: %w", err)
	}

	mode := cipher.NewCBCDecrypter(block, iv)
	decrypted := make([]byte, len(ciphertext))
	mode.CryptBlocks(decrypted, ciphertext)

	if len(decrypted) == 0 {
		return decrypted, nil
	}

	paddingLen := int(decrypted[len(decrypted)-1])
	if paddingLen <= 0 || paddingLen > aes.BlockSize {
		return nil, errors.New("invalid PKCS#7 padding")
	}

	for i := len(decrypted) - paddingLen; i < len(decrypted); i++ {
		if int(decrypted[i]) != paddingLen {
			return nil, errors.New("invalid PKCS#7 padding")
		}
	}

	return decrypted[:len(decrypted)-paddingLen], nil
}
