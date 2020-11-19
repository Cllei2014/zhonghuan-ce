package sm2

import (
	"encoding/pem"
	"github.com/Hyperledger-TWGC/tjfoc-gm/x509"
	"github.com/aliyun/alibaba-cloud-sdk-go/services/kms"
	"os"
	"testing"
)

func setupFixture() *kms.Client {
	client, err := kms.NewClientWithAccessKey(os.Getenv("ALIBABA_CLOUD_REGION"),
		os.Getenv("ALIBABA_CLOUD_ACCESS_KEY_ID"), os.Getenv("ALIBABA_CLOUD_ACCESS_KEY_SECRET"))
	if err != nil {
		panic(err)
	}
	return client
}

func TestParsePublicKey(t *testing.T) {
	client := setupFixture()

	sm2, err := CreateSm2KeyAdapter(client, SignAndVerify, "")

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

	//if err = sm2.ScheduleKeyDeletion(); err != nil {
	//	t.Fatalf("failed to schedule sm2 key deletion, Got err: %s", err)
	//}
}
