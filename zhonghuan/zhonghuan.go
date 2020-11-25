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
	"log"
	"unsafe"
)

const logHeader = "ZhongHuan lib:"
const keyLen = 64

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

func GenerateKey(config, userLabel, userPin string) ([]byte, error) {
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
	//sm2PublicKey, err := x509.ParseSm2PublicKey(publicKey)
	//if err != nil {
	//	return nil, err
	//}
	//log.Println(logHeader, "Transform to SM2 PublicKey Success!")
	return publicKey, nil
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
	return nil
}
