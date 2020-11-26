package zhonghuan

import (
	"log"
	"math/rand"
)

var letters = []byte("01234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")
var lettersLen = len(letters)

const labelLen = 32
const pinLen = 32

func randomLetters(length int) string {
	res := make([]byte, length)
	for i, _ := range res {
		res[i] = letters[rand.Int()%lettersLen]
	}
	return string(res)
}

func GenerateUser() (label string, pin string) {
	label = randomLetters(labelLen)
	pin = randomLetters(pinLen)
	log.Println("ZhongHuan lib: Generate userLabel:", label, ", userPin:", pin)
	return
}
