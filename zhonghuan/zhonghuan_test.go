package zhonghuan

import (
	"fmt"
	"github.com/stretchr/testify/assert"
	"testing"
)

func setUp() (pcCfg, pcUserLabel, pcUserPin string) {
	pcCfg = "dCj3on8SFj9054UDi+t5q1EEIwR1hGm95P1g8ihNfq9aWH0qDJE9uYa+zQol6C7uDVGJVnVep4p27OcYbll80SeqGsyetUWjmZ0GRsMeRywcYc6ApsXaXBg6XHF9JVspJyVGUWaP4sRdTEvnUwolIQ=="
	pcUserLabel = "13800138000"
	pcUserPin = "12345678"
	return
}

func TestGenerateKey(t *testing.T) {
	pcCfg, pcUserLabel, pcUserPin := setUp()
	_, err := GenerateKey(pcCfg, pcUserLabel, pcUserPin)
	assert.Nil(t, err, fmt.Sprint("Generate key error: ", err))
}
