package sm2

import (
	"crypto"
	"errors"
	sm2TJ "github.com/Hyperledger-TWGC/tjfoc-gm/sm2"
	"github.com/tw-bc-group/mock-collaborative-encryption-lib/zhonghuan"
	"io"
	"os"
)

type KeyAdapter struct {
	config    string
	keyID     string
	publicKey *sm2TJ.PublicKey
}

func CreateSm2KeyAdapter(keyID string) (*KeyAdapter, error) {
	config := os.Getenv("ZHONGHUAN_CE_CONFIG")
	if len(config) == 0 {
		return nil, errors.New("ZHONGHUAN_CE_CONFIG environment variable should be set!")
	}
	sm2 := &KeyAdapter{
		config:    config,
		keyID:     keyID,
		publicKey: nil,
	}
	if keyID == "" {
		userLabel, userPin := zhonghuan.GenerateUser()
		sm2.keyID = zhonghuan.KeyIdFromLabelAndPin(userLabel, userPin)
		err := sm2.CreateKey()
		if err != nil {
			return nil, err
		}
	} else {
		userLabel, _ := zhonghuan.LabelAndPinFromKeyId(sm2.keyID)
		publicKey, err := zhonghuan.GetPublicKey(config, userLabel)
		if err != nil {
			return nil, err
		}
		sm2.publicKey = publicKey
	}
	return sm2, nil
}

func (sm2 *KeyAdapter) KeyID() string {
	return sm2.keyID
}

func (sm2 *KeyAdapter) CreateKey() error {
	userLabel, userPin := zhonghuan.LabelAndPinFromKeyId(sm2.keyID)
	publicKey, err := zhonghuan.GenerateKey(sm2.config, userLabel, userPin)
	sm2.publicKey = publicKey
	return err
}

func (sm2 *KeyAdapter) GetPublicKey() *sm2TJ.PublicKey {
	return sm2.publicKey
}

func (sm2 *KeyAdapter) AsymmetricSign(message []byte) ([]byte, error) {
	userLabel, userPin := zhonghuan.LabelAndPinFromKeyId(sm2.keyID)
	return zhonghuan.Sign(sm2.config, userLabel, userPin, message)
}

func (sm2 *KeyAdapter) AsymmetricVerify(message, signature []byte) (bool, error) {
	return zhonghuan.Verify(sm2.config, message, signature, sm2.publicKey)
}

func (sm2 *KeyAdapter) AsymmetricEncrypt(plainText []byte) ([]byte, error) {
	cipherText, err := zhonghuan.AsymmetricEncrypt(sm2.config, plainText, sm2.publicKey)
	if err != nil {
		return nil, err
	}

	return cipherText, nil
}

func (sm2 *KeyAdapter) AsymmetricDecrypt(cipherText []byte) ([]byte, error) {
	userLabel, userPin := zhonghuan.LabelAndPinFromKeyId(sm2.keyID)
	return zhonghuan.AsymmetricDecrypt(sm2.config, userLabel, userPin, cipherText)
}

func (sm2 *KeyAdapter) KeyDeletion() error {
	userLabel, _ := zhonghuan.LabelAndPinFromKeyId(sm2.keyID)
	return zhonghuan.DeleteKey(sm2.config, userLabel)
}

// implements crypto.Signer
func (adapter *KeyAdapter) Public() crypto.PublicKey {
	return adapter.publicKey
}

func (adapter *KeyAdapter) Sign(_ io.Reader, message []byte, _ crypto.SignerOpts) ([]byte, error) {
	return adapter.AsymmetricSign(message)
}

// implements crypto.Decrypter
func (adapter *KeyAdapter) Decrypt(_ io.Reader, msg []byte, _ crypto.DecrypterOpts) ([]byte, error) {
	return adapter.AsymmetricDecrypt(msg)
}
