package zhonghuan

import (
	"fmt"
	"github.com/stretchr/testify/assert"
	"testing"
)

func setUp() (config, userLabel, userPin string) {
	config = "dCj3on8SFj9054UDi+t5q1EEIwR1hGm95P1g8ihNfq9aWH0qDJE9uYa+zQol6C7uDVGJVnVep4p27OcYbll80SeqGsyetUWjmZ0GRsMeRywcYc6ApsXaXBg6XHF9JVspJyVGUWaP4sRdTEvnUwolIQ=="
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

	_, err := GenerateKey(config, userLabel, userPin)
	assert.Nil(t, err, fmt.Sprint("Generate key error: ", err))

	_, err = GetPublicKey(config, userLabel)
	assert.Nil(t, err, fmt.Sprint("Get key error: ", err))

	err = DeleteKey(config, userLabel)
	assert.Nil(t, err, fmt.Sprint("Delete key error: ", err))
}
