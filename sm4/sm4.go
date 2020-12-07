package sm4

import (
	"crypto/rand"
	"github.com/Hyperledger-TWGC/tjfoc-gm/sm4"
	"github.com/aliyun/alibaba-cloud-sdk-go/services/kms"
	log "github.com/sirupsen/logrus"
	"github.com/tw-bc-group/zhonghuan-ce/common"
)

var zhLog = log.WithFields(log.Fields{"lib": "tjfoc sm4 in ZhongHuan-CE"})

type KeyAdapter struct {
	client *kms.Client
	keyID  string
}

func init() {
	common.SetLogLevelByEnv()
}

func CreateSm4KeyAdapter(keyID string) (*KeyAdapter, error) {
	client := common.CreateClient()

	adapter := &KeyAdapter{
		client: client,
	}

	if keyID == "" {
		err := adapter.CreateKey()
		if err != nil {
			return nil, err
		}
	}

	return adapter, nil
}

func (adapter *KeyAdapter) CreateKey() error {
	key := make([]byte, 16)
	_, err := rand.Read(key)
	if err != nil {
		return err
	}
	keyDbId, _ := common.AddSm4Key(string(key))
	adapter.keyID = common.KeyIdFrom(keyDbId)
	zhLog.Debug("Create new key with mock keyId:", keyDbId)
	return nil
}

func (adapter *KeyAdapter) getKey() ([]byte, error) {
	key, err := common.GetSm4Key(common.KeyDbIdFrom(adapter.keyID))
	if err != nil {
		return nil, err
	}
	return []byte(key), nil
}

func (adapter *KeyAdapter) Encrypt(plainText []byte) ([]byte, error) {
	key, err := adapter.getKey()
	if err != nil {
		return nil, err
	}
	cipherText, err := sm4.Sm4OFB(key, plainText, true)
	if err != nil {
		return nil, err
	}
	zhLog.Debug("Encrypt with mock keyId:", adapter.keyID)
	return cipherText, nil
}

func (adapter *KeyAdapter) Decrypt(cipherText []byte) ([]byte, error) {
	key, err := adapter.getKey()
	if err != nil {
		return nil, err
	}
	plainText, err := sm4.Sm4OFB(key, cipherText, false)
	zhLog.Debug("Decrypt with mock keyId:", adapter.keyID)
	return plainText, nil
}

func (adapter *KeyAdapter) ScheduleKeyDeletion() error {
	return nil
}
