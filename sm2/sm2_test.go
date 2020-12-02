package sm2

import (
	"github.com/Hyperledger-TWGC/tjfoc-gm/sm2"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestParsePublicKey(t *testing.T) {
	var keyID string

	{
		adapter, err := CreateSm2KeyAdapter("")
		if err != nil {
			t.Fatalf("failed to create sm2 key, Got err: %s", err)
		}
		keyID = adapter.KeyID()
	}

	adapter, err := CreateSm2KeyAdapter(keyID)
	if err != nil {
		t.Fatalf("failed to create sm2 key, Got err: %s", err)
	}

	publicKey := adapter.PublicKey()
	if publicKey == nil {
		t.Fatalf("failed to get public key, Got err: %s", err)
	}

	if err = adapter.KeyDeletion(); err != nil {
		t.Fatalf("failed to schedule sm2 key deletion, Got err: %s", err)
	}
}

func TestSignAndVerify(t *testing.T) {
	adapter, err := CreateSm2KeyAdapter("")

	if err != nil {
		t.Fatalf("failed to create sm2 sign key, Got err: %s", err)
	}

	message := []byte("test sign verify")

	signature, err := adapter.AsymmetricSign(message)
	if err != nil {
		t.Fatalf("failed to sm2 asymmetric sign, Got err: %s", err)
	}

	verify, err := adapter.AsymmetricVerify(message, signature)
	if err != nil {
		t.Fatalf("failed to sm2 asymmetric verify, Got err: %s", err)
	}

	assert.Equal(t, verify, true, "verify should be success")

	if err = adapter.KeyDeletion(); err != nil {
		t.Fatalf("failed to schedule sm2 key deletion, Got err: %s", err)
	}
}

func TestSignAndVerifyWithPublic(t *testing.T) {
	adapter, err := CreateSm2KeyAdapter("")

	if err != nil {
		t.Fatalf("failed to create sm2 sign key, Got err: %s", err)
	}

	message := []byte("test sign verify")

	signature, err := adapter.AsymmetricSign(message)
	if err != nil {
		t.Fatalf("failed to sm2 asymmetric sign, Got err: %s", err)
	}

	publicKey := adapter.PublicKey()

	verify := publicKey.Verify(message, signature)

	assert.Equal(t, verify, true, "verify should be success")

	if err = adapter.KeyDeletion(); err != nil {
		t.Fatalf("failed to schedule sm2 key deletion, Got err: %s", err)
	}
}

func TestEncryptAndDecryptWithPublicKey(t *testing.T) {
	adapter, err := CreateSm2KeyAdapter("")

	if err != nil {
		t.Fatalf("failed to create sm2 key, Got err: %s", err)
	}

	message := []byte("test crypto")

	publicKey := adapter.PublicKey()

	cipher, err := sm2.Encrypt(publicKey, message, nil)
	if err != nil {
		t.Fatalf("failed to sm2 asymmetric encrypt, Got err: %s", err)
	}

	decryptText, err := adapter.AsymmetricDecrypt(cipher)
	if err != nil {
		t.Fatalf("failed to sm2 asymmetric decrypt, Got err: %s", err)
	}

	assert.Equal(t, message, decryptText, "decrypted should same as plain text")

	if err = adapter.KeyDeletion(); err != nil {
		t.Fatalf("failed to schedule sm2 key deletion, Got err: %s", err)
	}
}

func TestEncryptAndDecrypt(t *testing.T) {
	adapter, err := CreateSm2KeyAdapter("")

	if err != nil {
		t.Fatalf("failed to create sm2 key, Got err: %s", err)
	}

	message := []byte("test crypto")

	cipherText, err := adapter.AsymmetricEncrypt(message)
	if err != nil {
		t.Fatalf("failed to sm2 asymmetric encrypt, Got err: %s", err)
	}

	decryptText, err := adapter.AsymmetricDecrypt(cipherText)
	if err != nil {
		t.Fatalf("failed to sm2 asymmetric decrypt, Got err: %s", err)
	}

	assert.Equal(t, message, decryptText, "decrypted should same as plain text")

	if err = adapter.KeyDeletion(); err != nil {
		t.Fatalf("failed to schedule sm2 key deletion, Got err: %s", err)
	}
}
