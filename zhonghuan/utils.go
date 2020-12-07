package zhonghuan

import (
	"github.com/google/uuid"
	"strings"
)

var letters = []byte("01234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")
var lettersLen = len(letters)

const Label_Len = 32
const Pin_Len = 32

func GenerateUser() (label string, pin string) {
	labelUUID, err := uuid.NewRandom()
	if err != nil {
		zhLog.Fatal("generate user label error")
	}
	pinUUID, err := uuid.NewRandom()
	if err != nil {
		zhLog.Fatal("generate user pin error")
	}
	label = strings.ReplaceAll(labelUUID.String(), "-", "")
	pin = strings.ReplaceAll(pinUUID.String(), "-", "")
	zhLog.Debug("Generate userLabel:", label, ", userPin:", pin)
	return
}

func LabelAndPinFromKeyId(keyId string) (label string, pin string) {
	return keyId[:Label_Len], keyId[Label_Len:]
}

func KeyIdFromLabelAndPin(label string, pin string) (keyId string) {
	return label + pin
}
