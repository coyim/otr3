package otr3

import (
	"crypto/aes"
	"crypto/cipher"
)

func counterEncipher(key, iv, src, dst []byte) error {
	aesCipher, err := aes.NewCipher(key)

	if err != nil {
		return err
	}

	ctr := cipher.NewCTR(aesCipher, iv)
	ctr.XORKeyStream(dst, src)

	return nil
}

func encrypt(key, data []byte) (dst []byte, err error) {
	dst = make([]byte, len(data))
	err = counterEncipher(key, dst[:aes.BlockSize], data, dst)
	return
}

func decrypt(key, dst, src []byte) error {
	return counterEncipher(key, make([]byte, aes.BlockSize), src, dst)
}
