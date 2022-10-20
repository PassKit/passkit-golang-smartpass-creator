package passkit_golang_smartpass_creator

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"strings"
)

func GenerateEncryptedSmartPassLink(fields map[string]string, distributionUrl, key string) (string, error) {

	if key == "" {
		return "", fmt.Errorf("key cannot be empty")
	}

	u, err := url.Parse(distributionUrl)
	if err != nil {
		return "", err
	}

	urlParts := strings.Split(strings.Trim(u.Path, "/"), "/")
	if len(urlParts) != 2 {
		return "", fmt.Errorf("invalid distribution URL")
	}

	jsonBytes, err := json.Marshal(fields)
	if err != nil {
		return "", err
	}

	var iv [aes.BlockSize]byte
	_, err = io.ReadFull(rand.Reader, iv[:])
	if err != nil {
		return "", err
	}

	k, err := hex.DecodeString(key)
	if err != nil {
		return "", err
	}

	encryptedPayload, err := encrypt(k, iv[:], jsonBytes, false)
	if err != nil {
		return "", err
	}

	b64 := base64.RawURLEncoding.EncodeToString(encryptedPayload)
	urlString := fmt.Sprintf("%s?data=%s&iv=%x", u.String(), b64, iv)

	return urlString, nil
}

func encrypt(key, iv, data []byte, prefixedIV bool) ([]byte, error) {
	padded, err := pkcs7Pad(data)
	if err != nil {
		return nil, err
	}
	c, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	cbc := cipher.NewCBCEncrypter(c, iv)
	if prefixedIV {
		cbc.CryptBlocks(padded[aes.BlockSize:], padded[aes.BlockSize:])
	} else {
		cbc.CryptBlocks(padded, padded)
	}
	return padded, nil
}

func pkcs7Pad(data []byte) ([]byte, error) {
	padlen := 1
	for ((len(data) + padlen) % aes.BlockSize) != 0 {
		padlen = padlen + 1
	}
	pad := bytes.Repeat([]byte{byte(padlen)}, padlen)
	return append(data, pad...), nil
}
