package zhonghuan

/*

#cgo CFLAGS: -I${SRCDIR}/include

#cgo LDFLAGS: -lxsign

#include "XSign.h"
#include "XDef.h"

*/
import "C"
import (
	"errors"
	"github.com/Hyperledger-TWGC/tjfoc-gm/sm2"
	"log"
	"math/big"
	"unsafe"
)

const logHeader = "ZhongHuan lib:"
const KEN_LEN = 64
const SIGNATURE_LEN = 64
const LEN_CIPHER_MORE_THAN_PLAIN = 96

func initialize(config string) (handle unsafe.Pointer, err error) {
	handle = unsafe.Pointer(C.HANDLE(C.NULL))
	res := uint32(C.X_Initialize(C.CString(config), &handle))
	if res != 0 {
		log.Printf("%s X_Initialize Error! ErrorCode=%X", logHeader, res)
		return nil, errors.New("X_Initialize Error!")
	}
	return handle, nil
}

func finalize(handle unsafe.Pointer) {
	C.X_Finalize(handle)
}

func sm2PublicKeyFromZH(zhKey []byte) *sm2.PublicKey {
	x := new(big.Int).SetBytes(zhKey[:KEN_LEN/2])
	y := new(big.Int).SetBytes(zhKey[KEN_LEN/2:])
	var sm2PublicKey = sm2.PublicKey{
		Curve: sm2.P256Sm2(),
		X:     x,
		Y:     y,
	}
	return &sm2PublicKey
}

func zhPublicKeyFromSM2(sm2Key *sm2.PublicKey) []byte {
	return append(sm2Key.X.Bytes(), sm2Key.Y.Bytes()...)
}

func cipherTextLenFromPlain(plainTextLen int) int {
	return plainTextLen + LEN_CIPHER_MORE_THAN_PLAIN
}

func plainTextLenFromCipher(cipherTextLen int) int {
	return cipherTextLen - LEN_CIPHER_MORE_THAN_PLAIN
}

func GetVersion() (uint32, error) {
	version := C.UINT32(0)
	res := uint32(C.X_GetVersion(&version))
	if res != 0 {
		log.Printf("%s X_GetVersion Error! ErrorCode=%X", logHeader, res)
		return 0, errors.New("X_GetVersion Error!")
	}
	log.Printf("%s X_GetVersion Success! Version=%X", logHeader, res)
	return uint32(version), nil
}

func GenerateKey(config, userLabel, userPin string) (*sm2.PublicKey, error) {
	handle, err := initialize(config)
	if err != nil {
		return nil, err
	}
	defer finalize(handle)

	var cPublicKey [KEN_LEN]C.UCHAR
	cKeyLen := C.UINT32(KEN_LEN)
	res := uint32(C.X_GenKey(
		handle,
		C.CString(userLabel),
		C.CString(userPin),
		&cPublicKey[0],
		&cKeyLen))
	if res != 0 {
		log.Printf("%s X_GenKey Error! ErrorCode=%X", logHeader, res)
		return nil, errors.New("X_GenKey Error!")
	}
	log.Println(logHeader, "X_GenKey Success!")

	publicKey := C.GoBytes(unsafe.Pointer(&cPublicKey[0]), C.int(KEN_LEN))
	return sm2PublicKeyFromZH(publicKey), nil
}

func DeleteKey(config, userLabel string) error {
	handle, err := initialize(config)
	if err != nil {
		return err
	}
	defer finalize(handle)

	res := uint32(C.X_DelKey(handle, C.CString(userLabel)))
	if res != 0 {
		log.Printf("%s X_DelKey Error! ErrorCode=%X", logHeader, res)
		return errors.New("X_DelKey Error")
	}
	log.Println(logHeader, "X_DelKey Success!")
	return nil
}

func GetPublicKey(config, userLabel string) (*sm2.PublicKey, error) {
	handle, err := initialize(config)
	if err != nil {
		return nil, err
	}
	defer finalize(handle)

	var cPublicKey [KEN_LEN]C.UCHAR
	cKeyLen := C.UINT32(KEN_LEN)
	res := uint32(C.X_GetPublicKey(
		handle,
		C.CString(userLabel),
		&cPublicKey[0],
		&cKeyLen))
	if res != 0 {
		log.Printf("%s X_GetPublicKey Error! ErrorCode=%X", logHeader, res)
		return nil, errors.New("X_GetPublicKey Error!")
	}
	log.Println(logHeader, "X_GetPublicKey Success!")

	publicKey := C.GoBytes(unsafe.Pointer(&cPublicKey[0]), C.int(KEN_LEN))
	return sm2PublicKeyFromZH(publicKey), nil
}

func Sign(config, userLabel, userPin string, message []byte) ([]byte, error) {
	handle, err := initialize(config)
	if err != nil {
		return nil, err
	}
	defer finalize(handle)

	var cSignature [SIGNATURE_LEN]C.UCHAR
	cSignatureLen := C.UINT32(KEN_LEN)
	res := uint32(C.X_Sign(
		handle,
		C.CString(userLabel),
		C.CString(userPin),
		(*C.uchar)(unsafe.Pointer(&message[0])),
		C.UINT32(len(message)),
		&cSignature[0],
		&cSignatureLen))
	if res != 0 {
		log.Printf("%s X_Sign Error! ErrorCode=%X", logHeader, res)
		return nil, errors.New("X_Sign Error!")
	}
	log.Println(logHeader, "X_Sign Success!")
	signature := C.GoBytes(unsafe.Pointer(&cSignature[0]), C.int(cSignatureLen))
	return signature, nil
}

func Verify(config string, message, signature []byte, publicKey *sm2.PublicKey) (bool, error) {
	handle, err := initialize(config)
	if err != nil {
		return false, err
	}
	defer finalize(handle)

	cPublicKey := zhPublicKeyFromSM2(publicKey)
	res := uint32(C.X_Verify(
		(*C.uchar)(unsafe.Pointer(&message[0])),
		C.UINT32(len(message)),
		(*C.uchar)(unsafe.Pointer(&cPublicKey[0])),
		C.UINT32(len(cPublicKey)),
		(*C.uchar)(unsafe.Pointer(&signature[0])),
		C.UINT32(len(signature))))
	if res == C.ERR_VERIFY_FAILED {
		log.Println(logHeader, "X_Verify Failed!")
		return false, nil
	}
	if res != 0 {
		log.Printf("%s X_Verify Error! ErrorCode=%X", logHeader, res)
		return false, errors.New("X_Verify Error!")
	}
	log.Println(logHeader, "X_Verify Success!")
	return true, nil
}

func AsymmetricEncrypt(config string, plainText []byte, publicKey *sm2.PublicKey) ([]byte, error) {
	handle, err := initialize(config)
	if err != nil {
		return nil, err
	}
	defer finalize(handle)

	cPublicKey := zhPublicKeyFromSM2(publicKey)
	cipherTextLen := cipherTextLenFromPlain(len(plainText))
	cCipherTextLen := C.UINT32(cipherTextLen)
	cipherText := make([]byte, cipherTextLen)
	res := uint32(C.X_AsymmEncrypt(
		(*C.UCHAR)(unsafe.Pointer(&cPublicKey[0])),
		C.UINT32(len(cPublicKey)),
		(*C.UCHAR)(unsafe.Pointer(&plainText[0])),
		C.UINT32(len(plainText)),
		(*C.UCHAR)(unsafe.Pointer(&cipherText[0])),
		&cCipherTextLen))
	if res != 0 {
		log.Printf("%s X_AsymmEncrypt Error! ErrorCode=%X", logHeader, res)
		return nil, errors.New("X_AsymmEncrypt Error!")
	}
	log.Println(logHeader, "X_AsymmEncrypt Success!")
	return cipherText, nil
}

func AsymmetricDecrypt(config, userLabel, userPin string, cipherText []byte) ([]byte, error) {
	handle, err := initialize(config)
	if err != nil {
		return nil, err
	}
	defer finalize(handle)

	palinTextLen := plainTextLenFromCipher(len(cipherText))
	cPlainTextLen := C.UINT32(palinTextLen)
	plainText := make([]byte, palinTextLen)
	res := uint32(C.X_AsymmDecrypt(
		handle,
		C.CString(userLabel),
		C.CString(userPin),
		(*C.UCHAR)(unsafe.Pointer(&cipherText[0])),
		C.UINT32(len(cipherText)),
		(*C.UCHAR)(unsafe.Pointer(&plainText[0])),
		&cPlainTextLen))
	if res != 0 {
		log.Printf("%s X_AsymmDecrypt Error! ErrorCode=%X", logHeader, res)
		return nil, errors.New("X_AsymmDecrypt Error!")
	}
	log.Println(logHeader, "X_AsymmDecrypt Success!")
	return plainText, nil
}
