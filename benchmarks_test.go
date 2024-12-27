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

func BenchmarkRSAKeyGeneration(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, err := rsa.GenerateKey(rand.Reader, bitLength)
		require.NoError(b, err)
	}
}

func BenchmarkECDSAKeyGeneration(b *testing.B) {
	curve := elliptic.P256()

	for i := 0; i < b.N; i++ {
		_, err := ecdsa.GenerateKey(curve, rand.Reader)
		require.NoError(b, err)
	}
}

func BenchmarkDirectMessageRSA(b *testing.B) {
	// DM parties
	senderID := uuid.New()
	sender, err := rsa.GenerateKey(rand.Reader, bitLength)
	require.NoError(b, err)

	receiverID := uuid.New()
	receiver, err := rsa.GenerateKey(rand.Reader, bitLength)
	require.NoError(b, err)

	for i := 0; i < b.N; i++ {
		// Message
		var messageBytes []byte
		{
			// Contents of the message
			payload, err := json.Marshal(MessagePayload{
				PreviousMessageHash: nil,
				Content:             "Hello World!",
			})
			require.NoError(b, err)

			// Encrypt
			encryptedPayload, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, &receiver.PublicKey, payload, label)
			require.NoError(b, err)

			// Sign the content for authentication
			hasher := sha256.New()
			hasher.Write(encryptedPayload)
			signature, err := rsa.SignPSS(rand.Reader, sender, crypto.SHA256, hasher.Sum(nil), nil)
			require.NoError(b, err)

			// Create message
			messageBytes, err = json.Marshal(Message{
				Sender:    senderID,
				Receiver:  receiverID,
				Payload:   encryptedPayload,
				Signature: signature,
			})
			require.NoError(b, err)
		}

		// `message` can be safely sent over the wire

		// Receive JSON
		var message Message
		err = json.Unmarshal(messageBytes, &message)
		require.NoError(b, err)

		// Verify signature
		hasher := sha256.New()
		hasher.Write(message.Payload)
		err = rsa.VerifyPSS(&sender.PublicKey, crypto.SHA256, hasher.Sum(nil), message.Signature, nil)
		require.NoError(b, err)

		// Decrypt
		decryptedPayload, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, receiver, message.Payload, label)
		require.NoError(b, err)

		// Unmarshal payload
		var payload MessagePayload
		err = json.Unmarshal(decryptedPayload, &payload)
		require.NoError(b, err)

		// Should be the same as sent
		require.Empty(b, payload.PreviousMessageHash)
		require.Equal(b, payload.Content, "Hello World!")
	}
}

func BenchmarkDirectMessageECDSA(b *testing.B) {
	curve := elliptic.P256()

	// DM parties
	senderID := uuid.New()
	sender, err := ecdsa.GenerateKey(curve, rand.Reader)
	require.NoError(b, err)

	receiverID := uuid.New()
	receiver, err := ecdsa.GenerateKey(curve, rand.Reader)
	require.NoError(b, err)

	// ECDH keys for key exchange
	senderECDH, err := sender.ECDH()
	require.NoError(b, err)

	receiverECDH, err := receiver.ECDH()
	require.NoError(b, err)

	// Key exchange
	senderSharedSecret, err := senderECDH.ECDH(receiverECDH.PublicKey())
	require.NoError(b, err)

	receiverSharedSecret, err := receiverECDH.ECDH(senderECDH.PublicKey())
	require.NoError(b, err)

	require.Equal(b, senderSharedSecret, receiverSharedSecret)
	secret := senderSharedSecret

	// Get a shared IV using secret
	hkdf := hkdf.New(sha256.New, secret, nil, nil)
	iv := make([]byte, aes.BlockSize)
	_, err = hkdf.Read(iv)
	require.NoError(b, err)

	for i := 0; i < b.N; i++ {
		// Message
		var messageBytes []byte
		{
			payload, err := json.Marshal(MessagePayload{
				PreviousMessageHash: nil,
				Content:             "Hello World!",
			})
			require.NoError(b, err)

			// Encrypt payload
			assert.Equal(b, len(secret), 32) // Ensure we are using AES-256
			block, err := aes.NewCipher(secret)
			require.NoError(b, err)

			padding := aes.BlockSize - len(payload)%aes.BlockSize
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
			require.NoError(b, err)

			// Create message
			messageBytes, err = json.Marshal(Message{
				Sender:    senderID,
				Receiver:  receiverID,
				Payload:   encryptedPayload,
				Signature: signature,
			})
			require.NoError(b, err)
		}

		// `message` is safe to send over the write

		// Receive JSON
		var message Message
		err = json.Unmarshal(messageBytes, &message)
		require.NoError(b, err)

		// Verify signature
		hasher := sha256.New()
		hasher.Write(message.Payload)
		isSignatureValid := ecdsa.VerifyASN1(&sender.PublicKey, hasher.Sum(nil), message.Signature)
		require.True(b, isSignatureValid)

		// Decrypt payload
		assert.Equal(b, len(secret), 32) // Ensure we are using AES-256
		block, err := aes.NewCipher(secret)
		require.NoError(b, err)

		decryptedPayload := make([]byte, len(message.Payload))
		mode := cipher.NewCBCDecrypter(block, iv)
		mode.CryptBlocks(decryptedPayload, message.Payload)

		// Unmarshal decrypted payload
		var payload MessagePayload
		err = json.Unmarshal(bytes.TrimSpace(decryptedPayload), &payload)
		require.NoError(b, err)

		// Should be equal
		require.Empty(b, payload.PreviousMessageHash)
		require.Equal(b, payload.Content, "Hello World!")
	}
}
