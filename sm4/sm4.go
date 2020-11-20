package sm4

import (
	"crypto/rand"
	sm4TJ "github.com/Hyperledger-TWGC/tjfoc-gm/sm4"
	"github.com/aliyun/alibaba-cloud-sdk-go/services/kms"
	"github.com/tw-bc-group/mock-collaborative-encryption-lib/utils"
)

const requestScheme = "https"

const mockKeyVersionId = "mockKeyVersionId"
const logHeader = "Mock ce sm2: "

var mockSm4Keys []*sm4TJ.SM4Key

type KeyAdapter struct {
	client *kms.Client
	keyID  string
}

func CreateSm4KeyAdapter(client *kms.Client, keyID string) (*KeyAdapter, error) {
	sm4 := &KeyAdapter{
		client: client,
	}

	if keyID == "" {
		err := sm4.CreateKey()
		if err != nil {
			return nil, err
		}
	}

	return sm4, nil
}

func (sm4 *KeyAdapter) CreateKey() error {
	key := make([]byte, 16)
	_, err := rand.Read(key)
	if err != nil {
		return err
	}
	id, _ := utils.AddSm4Key(string(key))
	sm4.keyID = utils.KeyIdFrom(id)
	return nil
}

func (sm4 *KeyAdapter) getKey() ([]byte, error) {
	key, err := utils.GetSm4Key(utils.KeyDbIdFrom(sm4.keyID))
	if err != nil {
		return nil, err
	}
	return []byte(key), nil
}

func (sm4 *KeyAdapter) Encrypt(plainText []byte) ([]byte, error) {
	key, err := sm4.getKey()
	if err != nil {
		return nil, err
	}
	cipherText, err := sm4TJ.Sm4OFB(key, plainText, true)
	if err != nil {
		return nil, err
	}
	return cipherText, nil
}

func (sm4 *KeyAdapter) Decrypt(cipherText []byte) ([]byte, error) {
	key, err := sm4.getKey()
	if err != nil {
		return nil, err
	}
	plainText, err := sm4TJ.Sm4OFB(key, cipherText, false)
	return plainText, nil
}

func (sm4 *KeyAdapter) ScheduleKeyDeletion() error {
	return nil
}
