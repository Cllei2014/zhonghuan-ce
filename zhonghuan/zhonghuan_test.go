package zhonghuan

import (
	"crypto/rand"
	"fmt"
	"github.com/stretchr/testify/assert"
	"os"
	"testing"
)

func setUp() (config, userLabel, userPin string) {
	config = os.Getenv("ZHONGHUAN_CE_CONFIG")
	if len(config) == 0 {
		panic("ZHONGHUAN_CE_CONFIG environment variable should be set!")
	}
	userLabel = "13800138000"
	userPin = "12345678"
	return
}

func TestGetVersion(t *testing.T) {
	_, err := GetVersion()
	assert.Nil(t, err, fmt.Sprint("Get zhonghuan lib version version error: ", err))
}

func TestGenerateAndGetAndDeleteKey(t *testing.T) {
	config, userLabel, userPin := setUp()

	publicKey, err := GenerateKey(config, userLabel, userPin)
	assert.Nil(t, err, fmt.Sprint("Generate key error: ", err))
	_, err = publicKey.EncryptAsn1([]byte("data"), rand.Reader)
	assert.Nil(t, err, fmt.Sprint("Public key encrypt error: ", err))

	_, err = GetPublicKey(config, userLabel)
	assert.Nil(t, err, fmt.Sprint("Get key error: ", err))

	err = DeleteKey(config, userLabel)
	assert.Nil(t, err, fmt.Sprint("Delete key error: ", err))
}

func TestSignAndVerify(t *testing.T) {
	config, userLabel, userPin := setUp()

	publicKey, _ := GenerateKey(config, userLabel, userPin)

	message := []byte("sign message")
	signature, err := Sign(config, userLabel, userPin, message)
	assert.Nil(t, err, fmt.Sprint("Sign error: ", err))

	res, err := Verify(config, message, signature, publicKey)
	assert.Nil(t, err, fmt.Sprint("Verify error: ", err))
	assert.True(t, res, "Verify error: result should be true")

	wrongMessage := []byte("wrong message")
	res, err = Verify(config, wrongMessage, signature, publicKey)
	assert.Nil(t, err, fmt.Sprint("Verify error: ", err))
	assert.False(t, res, "Verify error: result should be false")
}

func TestAsymmetricEncryptAndDecrypt(t *testing.T) {
	config, userLabel, userPin := setUp()

	publicKey, _ := GenerateKey(config, userLabel, userPin)

	plainText := []byte("plain text")
	cipherText, err := AsymmetricEncrypt(config, plainText, publicKey)
	assert.Nil(t, err, fmt.Sprint("Encrypt error: ", err))

	decryptedPlainText, err := AsymmetricDecrypt(config, userLabel, userPin, cipherText)
	assert.Nil(t, err, fmt.Sprint("Decrypt error: ", err))
	assert.Equal(t, plainText, decryptedPlainText, "Decrypted text should equal plain text")
}
