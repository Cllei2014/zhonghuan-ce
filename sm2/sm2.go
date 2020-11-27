package sm2

import (
	"crypto"
	"errors"
	sm2TJ "github.com/Hyperledger-TWGC/tjfoc-gm/sm2"
	"github.com/tw-bc-group/zhonghuan-ce/zhonghuan"
	"io"
	"os"
)

type KeyAdapter struct {
	config string
	keyID  string
}

func CreateSm2KeyAdapter(keyID string) (*KeyAdapter, error) {

	config := os.Getenv("ZHONGHUAN_CE_CONFIG")
	if len(config) == 0 {
		return nil, errors.New("ZHONGHUAN_CE_CONFIG environment variable should be set!")
	}
	sm2 := &KeyAdapter{
		config: config,
		keyID:  keyID,
	}
	if keyID == "" {
		userLabel, userPin := zhonghuan.GenerateUser()
		sm2.keyID = zhonghuan.KeyIdFromLabelAndPin(userLabel, userPin)
		err := sm2.CreateKey()
		if err != nil {
			return nil, err
		}
	}
	return sm2, nil
}

func (sm2 *KeyAdapter) KeyID() string {
	return sm2.keyID
}

func (sm2 *KeyAdapter) CreateKey() error {
	userLabel, userPin := zhonghuan.LabelAndPinFromKeyId(sm2.keyID)
	_, err := zhonghuan.GenerateKey(sm2.config, userLabel, userPin)
	return err
}

func (sm2 *KeyAdapter) GetPublicKey() (*sm2TJ.PublicKey, error) {
	userLabel, _ := zhonghuan.LabelAndPinFromKeyId(sm2.keyID)
	return zhonghuan.GetPublicKey(sm2.config, userLabel)
}

func (sm2 *KeyAdapter) AsymmetricSign(message []byte) ([]byte, error) {
	userLabel, userPin := zhonghuan.LabelAndPinFromKeyId(sm2.keyID)
	return zhonghuan.Sign(sm2.config, userLabel, userPin, message)
}

func (sm2 *KeyAdapter) AsymmetricVerify(message, signature []byte) (bool, error) {
	publicKey, err := sm2.GetPublicKey()
	if err != nil {
		return false, err
	}
	return zhonghuan.Verify(sm2.config, message, signature, publicKey)
}

func (sm2 *KeyAdapter) AsymmetricEncrypt(plainText []byte) (string, error) {
	publicKey, err := sm2.GetPublicKey()
	if err != nil {
		return "", err
	}
	cipherText, err := zhonghuan.AsymmetricEncrypt(sm2.config, plainText, publicKey)
	if err != nil {
		return "", err
	}

	return string(cipherText), nil
}

func (sm2 *KeyAdapter) AsymmetricDecrypt(cipherText string) ([]byte, error) {
	userLabel, userPin := zhonghuan.LabelAndPinFromKeyId(sm2.keyID)
	return zhonghuan.AsymmetricDecrypt(sm2.config, userLabel, userPin, []byte(cipherText))
}

func (sm2 *KeyAdapter) KeyDeletion() error {
	userLabel, _ := zhonghuan.LabelAndPinFromKeyId(sm2.keyID)
	return zhonghuan.DeleteKey(sm2.config, userLabel)
}

// implements crypto.Signer
func (sm2 *KeyAdapter) TryIntoCryptoSigner() (crypto.Signer, error) {
	pubKey, err := sm2.GetPublicKey()
	if err != nil {
		return nil, err
	}

	return &cryptoSigner{adapter: sm2, pubKey: pubKey}, nil
}

type cryptoSigner struct {
	adapter *KeyAdapter
	pubKey  crypto.PublicKey
}

func (c *cryptoSigner) Public() crypto.PublicKey {
	return c.pubKey
}

func (c *cryptoSigner) Sign(_ io.Reader, message []byte, _ crypto.SignerOpts) ([]byte, error) {
	signature, err := c.adapter.AsymmetricSign(message)
	if err != nil {
		return nil, err
	}
	return signature, nil
}
