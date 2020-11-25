package zhonghuan

/*

#cgo CFLAGS: -I${SRCDIR}/include

#cgo LDFLAGS: -L${SRCDIR}/lib -lxsign

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
const keyLen = 64
const hashLen = 1024

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

	var cPublicKey [keyLen]C.UCHAR
	cKeyLen := C.UINT32(keyLen)
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

	publicKey := C.GoBytes(unsafe.Pointer(&cPublicKey[0]), C.int(keyLen))
	x := new(big.Int).SetBytes(publicKey[:keyLen/2])
	y := new(big.Int).SetBytes(publicKey[keyLen/2:])
	var sm2PublicKey = sm2.PublicKey{
		Curve: sm2.P256Sm2(),
		X:     x,
		Y:     y,
	}
	log.Println(logHeader, "Transform zhonghuan publicKey to SM2 publicKey Success!")
	return &sm2PublicKey, nil
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

func GetPublicKey(config, userLabel string) ([]byte, error) {
	handle, err := initialize(config)
	if err != nil {
		return nil, err
	}
	defer finalize(handle)

	var cPublicKey [keyLen]C.UCHAR
	cKeyLen := C.UINT32(keyLen)
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

	publicKey := C.GoBytes(unsafe.Pointer(&cPublicKey[0]), C.int(keyLen))
	return publicKey, nil
}
