package sm2

import (
	"crypto/rand"
	"errors"
	sm2TJ "github.com/Hyperledger-TWGC/tjfoc-gm/sm2"
	"github.com/Hyperledger-TWGC/tjfoc-gm/x509"
	"github.com/aliyun/alibaba-cloud-sdk-go/services/kms"
	"github.com/tw-bc-group/mock-collaborative-encryption-lib/common"
	"log"
)

const requestScheme = "https"
const sm2SignAlgorithm = "SM2DSA"
const sm2EncryptAlgorithm = "SM2PKE"

const mockKeyVersionId = "mockKeyVersionId"
const logHeader = "Mock ce sm2: "

const (
	EncryptAndDecrypt = 1 + iota
	SignAndVerify
)

type KeyAdapter struct {
	client     *kms.Client
	usage      int
	keyID      string
	keyVersion string
}

func CreateSm2KeyAdapter(usage int, keyID string) (*KeyAdapter, error) {
	if usage != EncryptAndDecrypt && usage != SignAndVerify {
		usage = SignAndVerify
	}

	client := common.CreateClient()

	sm2 := &KeyAdapter{
		client: client,
		usage:  usage,
	}

	if keyID == "" {
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

func (sm2 *KeyAdapter) getPrivateKey() (*sm2TJ.PrivateKey, error) {
	privateKeyPem, err := common.GetSm2Key(common.KeyDbIdFrom(sm2.keyID))
	if err != nil {
		return nil, err
	}
	privateKey, err := x509.ReadPrivateKeyFromMem([]byte(privateKeyPem), nil)
	if err != nil {
		return nil, err
	}
	return privateKey, nil
}

func (sm2 *KeyAdapter) CreateKey() error {
	privateKey, err := sm2TJ.GenerateKey(nil)
	if err != nil {
		return err
	}
	privateKeyPem, err := x509.WritePrivateKeyToMem(privateKey, nil)
	if err != nil {
		return err
	}
	keyDbId, err := common.AddSm2Key(string(privateKeyPem))
	if err != nil {
		return err
	}
	sm2.keyID = common.KeyIdFrom(keyDbId)
	sm2.keyVersion = mockKeyVersionId
	log.Println(logHeader, "Create new key with mock keyId:", keyDbId)
	return nil
}

func (sm2 *KeyAdapter) GetPublicKey() (string, error) {
	privateKey, err := sm2.getPrivateKey()
	if err != nil {
		return "", err
	}
	publicKeyPem, err := x509.WritePublicKeyToMem(&privateKey.PublicKey)
	if err != nil {
		return "", err
	}
	log.Println(logHeader, "Get public key with mock keyId:", sm2.keyID)

	return string(publicKeyPem), nil
}

func (sm2 *KeyAdapter) AsymmetricSign(message []byte) (string, error) {
	if sm2.keyID == "" || sm2.keyVersion == "" {
		return "", errors.New("need create sm2 key first")
	}

	if sm2.usage != SignAndVerify {
		return "", errors.New("unexpected key usage")
	}

	privateKey, err := sm2.getPrivateKey()
	if err != nil {
		return "", err
	}

	sign, err := privateKey.Sign(rand.Reader, message, nil)
	if err != nil {
		return "", err
	}
	log.Println(logHeader, "Sign with mock keyId:", sm2.keyID)

	return string(sign), nil
}

func (sm2 *KeyAdapter) AsymmetricVerify(message []byte, signature string) (bool, error) {
	if sm2.keyID == "" || sm2.keyVersion == "" {
		return false, errors.New("need create sm2 key first")
	}

	if sm2.usage != SignAndVerify {
		return false, errors.New("unexpected key usage")
	}

	privateKey, err := sm2.getPrivateKey()
	if err != nil {
		return false, err
	}
	log.Println(logHeader, "Verify with mock keyId:", sm2.keyID)

	return privateKey.PublicKey.Verify(message, []byte(signature)), nil
}

func (sm2 *KeyAdapter) AsymmetricEncrypt(plainText []byte) (string, error) {
	if sm2.keyID == "" || sm2.keyVersion == "" {
		return "", errors.New("need create sm2 key first")
	}

	if sm2.usage != EncryptAndDecrypt {
		return "", errors.New("unexpected key usage")
	}

	privateKey, err := sm2.getPrivateKey()
	if err != nil {
		return "", err
	}

	cipherText, err := privateKey.PublicKey.Encrypt(plainText, rand.Reader)
	if err != nil {
		return "", err
	}
	log.Println(logHeader, "Encrypt with mock keyId:", sm2.keyID)

	return string(cipherText), nil
}

func (sm2 *KeyAdapter) AsymmetricDecrypt(cipherText string) ([]byte, error) {
	if sm2.keyID == "" || sm2.keyVersion == "" {
		return nil, errors.New("need create sm2 key first")
	}

	if sm2.usage != EncryptAndDecrypt {
		return nil, errors.New("unexpected key usage")
	}

	privateKey, err := sm2.getPrivateKey()
	if err != nil {
		return nil, err
	}

	plainText, err := privateKey.Decrypt([]byte(cipherText))
	if err != nil {
		return nil, err
	}
	log.Println(logHeader, "Decrypt with mock keyId:", sm2.keyID)

	return plainText, nil
}

func (sm2 *KeyAdapter) ScheduleKeyDeletion() error {
	sm2.usage = -1
	log.Println(logHeader, "Schedule delete key with mock keyId:", sm2.keyID)
	return nil
}
