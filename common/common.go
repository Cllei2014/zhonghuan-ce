package common

import (
	"github.com/aliyun/alibaba-cloud-sdk-go/services/kms"
	log "github.com/sirupsen/logrus"
	"os"
)

var ZhongHuanLogLevel = "ZHONGHUAN_LOG_LEVEL"
var DebugLevel = "DEBUG"
var InfoLevel = "INFO"

func SetLogLevelByEnv() {
	switch os.Getenv(ZhongHuanLogLevel) {
	case DebugLevel:
		log.SetLevel(log.DebugLevel)
	default:
		log.SetLevel(log.InfoLevel)
	}
}

func CreateClient() *kms.Client {
	client, _ := kms.NewClientWithAccessKey("ALIBABA_CLOUD_REGION",
		"ALIBABA_CLOUD_ACCESS_KEY_ID", "ALIBABA_CLOUD_ACCESS_KEY_SECRET")
	return client
}
