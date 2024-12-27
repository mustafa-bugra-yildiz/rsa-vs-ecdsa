package main

import (
	"bytes"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/json"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/hkdf"
)

var bitLength = 4096
var label = []byte("message")

func TestDirectMessageRSA(t *testing.T) {
	// DM parties
	senderID := uuid.New()
	sender, err := rsa.GenerateKey(rand.Reader, bitLength)
	require.NoError(t, err)

	receiverID := uuid.New()
	receiver, err := rsa.GenerateKey(rand.Reader, bitLength)
	require.NoError(t, err)

	// Message
	var messageBytes []byte
	{
		// Contents of the message
		payload, err := json.Marshal(MessagePayload{
			PreviousMessageHash: nil,
			Content:             "Hello World!",
		})
		require.NoError(t, err)

		// Encrypt
		encryptedPayload, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, &receiver.PublicKey, payload, label)
		require.NoError(t, err)

		// Sign the content for authentication
		hasher := sha256.New()
		hasher.Write(encryptedPayload)
		signature, err := rsa.SignPSS(rand.Reader, sender, crypto.SHA256, hasher.Sum(nil), nil)
		require.NoError(t, err)

		// Create message
		messageBytes, err = json.Marshal(Message{
			Sender:    senderID,
			Receiver:  receiverID,
			Payload:   encryptedPayload,
			Signature: signature,
		})
		require.NoError(t, err)
	}

	// `message` can be safely sent over the wire

	// Receive JSON
	var message Message
	err = json.Unmarshal(messageBytes, &message)
	require.NoError(t, err)

	// Verify signature
	hasher := sha256.New()
	hasher.Write(message.Payload)
	err = rsa.VerifyPSS(&sender.PublicKey, crypto.SHA256, hasher.Sum(nil), message.Signature, nil)
	require.NoError(t, err)

	// Decrypt
	decryptedPayload, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, receiver, message.Payload, label)
	require.NoError(t, err)

	// Unmarshal payload
	var payload MessagePayload
	err = json.Unmarshal(decryptedPayload, &payload)
	require.NoError(t, err)

	// Should be the same as sent
	require.Empty(t, payload.PreviousMessageHash)
	require.Equal(t, payload.Content, "Hello World!")
}

func TestDirectMessageECDSA(t *testing.T) {
	curve := elliptic.P256()

	// DM parties
	senderID := uuid.New()
	sender, err := ecdsa.GenerateKey(curve, rand.Reader)
	require.NoError(t, err)

	receiverID := uuid.New()
	receiver, err := ecdsa.GenerateKey(curve, rand.Reader)
	require.NoError(t, err)

	// ECDH keys for key exchange
	senderECDH, err := sender.ECDH()
	require.NoError(t, err)

	receiverECDH, err := receiver.ECDH()
	require.NoError(t, err)

	// Key exchange
	senderSharedSecret, err := senderECDH.ECDH(receiverECDH.PublicKey())
	require.NoError(t, err)

	receiverSharedSecret, err := receiverECDH.ECDH(senderECDH.PublicKey())
	require.NoError(t, err)

	require.Equal(t, senderSharedSecret, receiverSharedSecret)
	secret := senderSharedSecret

	// Get a shared IV using secret
	hkdf := hkdf.New(sha256.New, secret, nil, nil)
	iv := make([]byte, aes.BlockSize)
	_, err = hkdf.Read(iv)
	require.NoError(t, err)

	// Message
	var messageBytes []byte
	{
		payload, err := json.Marshal(MessagePayload{
			PreviousMessageHash: nil,
			Content:             "Hello World!",
		})
		require.NoError(t, err)

		// Encrypt payload
		assert.Equal(t, len(secret), 32) // Ensure we are using AES-256
		block, err := aes.NewCipher(secret)
		require.NoError(t, err)

		padding := aes.BlockSize - len(payload)%aes.BlockSize // 16-bit aligned
		paddingBytes := make([]byte, padding)
		for i := range paddingBytes {
			paddingBytes[i] = ' '
		}

		payload = append(payload, paddingBytes...)

		encryptedPayload := make([]byte, len(payload))
		mode := cipher.NewCBCEncrypter(block, iv)
		mode.CryptBlocks(encryptedPayload, payload)

		// Sign encrypted payload
		hasher := sha256.New()
		hasher.Write(encryptedPayload)
		signature, err := ecdsa.SignASN1(rand.Reader, sender, hasher.Sum(nil))
		require.NoError(t, err)

		// Create message
		messageBytes, err = json.Marshal(Message{
			Sender:    senderID,
			Receiver:  receiverID,
			Payload:   encryptedPayload,
			Signature: signature,
		})
		require.NoError(t, err)
	}

	// `message` is safe to send over the write

	// Receive JSON
	var message Message
	err = json.Unmarshal(messageBytes, &message)
	require.NoError(t, err)

	// Verify signature
	hasher := sha256.New()
	hasher.Write(message.Payload)
	isSignatureValid := ecdsa.VerifyASN1(&sender.PublicKey, hasher.Sum(nil), message.Signature)
	require.True(t, isSignatureValid)

	// Decrypt payload
	assert.Equal(t, len(secret), 32) // Ensure we are using AES-256
	block, err := aes.NewCipher(secret)
	require.NoError(t, err)

	decryptedPayload := make([]byte, len(message.Payload))
	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(decryptedPayload, message.Payload)

	// Unmarshal decrypted payload
	var payload MessagePayload
	err = json.Unmarshal(bytes.TrimSpace(decryptedPayload), &payload)
	require.NoError(t, err)

	// Should be equal
	require.Empty(t, payload.PreviousMessageHash)
	require.Equal(t, payload.Content, "Hello World!")
}
