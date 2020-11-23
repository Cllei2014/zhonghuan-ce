package common

import "github.com/aliyun/alibaba-cloud-sdk-go/services/kms"

func CreateClient() *kms.Client {
	client, _ := kms.NewClientWithAccessKey("ALIBABA_CLOUD_REGION",
		"ALIBABA_CLOUD_ACCESS_KEY_ID", "ALIBABA_CLOUD_ACCESS_KEY_SECRET")
	return client
}
