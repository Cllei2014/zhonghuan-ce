package sm2

import (
	"encoding/pem"
	"github.com/Hyperledger-TWGC/tjfoc-gm/x509"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestParsePublicKey(t *testing.T) {
	sm2, err := CreateSm2KeyAdapter(SignAndVerify, "")

	if err != nil {
		t.Fatalf("failed to create sm2 sign key, Got err: %s", err)
	}

	pemPubKey, err := sm2.GetPublicKey()
	if err != nil {
		t.Fatalf("failed to get public key, Got err: %s", err)
	}

	block, _ := pem.Decode([]byte(pemPubKey))
	if block == nil {
		t.Fatalf("failed to pem decode publick key")
	}

	_, err = x509.ParseSm2PublicKey(block.Bytes)
	if err != nil {
		t.Fatalf("failed to parse public key, Got err: %s", err)
	}

	if err = sm2.ScheduleKeyDeletion(); err != nil {
		t.Fatalf("failed to schedule sm2 key deletion, Got err: %s", err)
	}
}

func TestSignAndVerify(t *testing.T) {
	sm2, err := CreateSm2KeyAdapter(SignAndVerify, "")

	if err != nil {
		t.Fatalf("failed to create sm2 sign key, Got err: %s", err)
	}

	message := []byte("test sign verify")

	signature, err := sm2.AsymmetricSign(message)
	if err != nil {
		t.Fatalf("failed to sm2 asymmetric sign, Got err: %s", err)
	}

	verify, err := sm2.AsymmetricVerify(message, signature)
	if err != nil {
		t.Fatalf("failed to sm2 asymmetric verify, Got err: %s", err)
	}

	assert.Equal(t, verify, true, "verify should be success")

	if err = sm2.ScheduleKeyDeletion(); err != nil {
		t.Fatalf("failed to schedule sm2 key deletion, Got err: %s", err)
	}
}

func TestEncryptAndDecrypt(t *testing.T) {
	sm2, err := CreateSm2KeyAdapter(EncryptAndDecrypt, "")

	if err != nil {
		t.Fatalf("failed to create sm2 encrypt key, Got err: %s", err)
	}

	message := []byte("test sign verify")

	plainText, err := sm2.AsymmetricEncrypt(message)
	if err != nil {
		t.Fatalf("failed to sm2 asymmetric encrypt, Got err: %s", err)
	}

	decryptText, err := sm2.AsymmetricDecrypt(plainText)
	if err != nil {
		t.Fatalf("failed to sm2 asymmetric decrypt, Got err: %s", err)
	}

	assert.Equal(t, message, decryptText, "decrypted should same as plain text")

	if err = sm2.ScheduleKeyDeletion(); err != nil {
		t.Fatalf("failed to schedule sm2 key deletion, Got err: %s", err)
	}
}
