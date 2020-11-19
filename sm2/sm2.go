package sm2

import (
	"encoding/base64"
	sm2TJ "github.com/Hyperledger-TWGC/tjfoc-gm/sm2"
	"github.com/Hyperledger-TWGC/tjfoc-gm/sm3"
	"github.com/Hyperledger-TWGC/tjfoc-gm/x509"
	"github.com/aliyun/alibaba-cloud-sdk-go/services/kms"
	"log"
	"strconv"
)

const requestScheme = "https"
const sm2SignAlgorithm = "SM2DSA"
const sm2EncryptAlgorithm = "SM2PKE"

const mockKeyVersionId = "mockKeyVersionId"

var mockPrivateKeys []*sm2TJ.PrivateKey

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

func keyUsageString(keyUsage int) string {
	switch keyUsage {
	case EncryptAndDecrypt:
		return "ENCRYPT/DECRYPT"
	default:
		return "SIGN/VERIFY"
	}
}

func sm3Digest(message []byte) string {
	return base64.StdEncoding.EncodeToString(sm3.Sm3Sum(message))
}

func CreateSm2KeyAdapter(client *kms.Client, usage int, keyID string) (*KeyAdapter, error) {
	if usage != EncryptAndDecrypt && usage != SignAndVerify {
		usage = SignAndVerify
	}

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

func (sm2 *KeyAdapter) CreateKey() error {
	privateKey, err := sm2TJ.GenerateKey(nil)
	if err != nil {
		return err
	}
	mockPrivateKeys = append(mockPrivateKeys, privateKey)
	mockKeyId := len(mockPrivateKeys) - 1

	sm2.keyID = strconv.Itoa(mockKeyId)
	sm2.keyVersion = mockKeyVersionId
	log.Println("Create new key with mock keyId:", mockKeyId)

	return nil
}

func (sm2 *KeyAdapter) GetPublicKey() (string, error) {
	mockKeyId, err := strconv.Atoi(sm2.keyID)
	if err != nil {
		return "", err
	}
	privateKey := mockPrivateKeys[mockKeyId]
	publicKeyPem, err := x509.WritePublicKeyToMem(&privateKey.PublicKey)
	if err != nil {
		return "", err
	}

	return string(publicKeyPem), nil
}
