package zhonghuan

import (
	"fmt"
	"log"
	"math/rand"
	"time"
)

var letters = []byte("01234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")
var lettersLen = len(letters)

const LABEL_LEN = 32
const PIN_LEN = 32

func randomLetters(length int) string {
	res := make([]byte, length)
	for i, _ := range res {
		res[i] = letters[rand.Int()%lettersLen]
	}
	return string(res)
}

func GenerateUser() (label string, pin string) {
	timestamp := fmt.Sprint(time.Now().UnixNano())
	label = timestamp + randomLetters(LABEL_LEN-len(timestamp))
	pin = randomLetters(PIN_LEN)
	log.Println("ZhongHuan lib: Generate userLabel:", label, ", userPin:", pin)
	return
}

func LabelAndPinFromKeyId(keyId string) (label string, pin string) {
	return keyId[:LABEL_LEN], keyId[LABEL_LEN:]
}

func KeyIdFromLabelAndPin(label string, pin string) (keyId string) {
	return label + pin
}
