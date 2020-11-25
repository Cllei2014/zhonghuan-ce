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
	"github.com/Hyperledger-TWGC/tjfoc-gm/x509"
	"log"
	"unsafe"
)

const logHeader = "ZhongHuan lib:"
const keyLen = 64

func GenerateKey(pcCfg, pcUserLabel, pcUserPin string) (*sm2.PublicKey, error) {
	handle := unsafe.Pointer(C.HANDLE(C.NULL))
	res := int(C.X_Initialize(C.CString(pcCfg), &handle))
	if res != 0 {
		log.Printf("%s X_Initialize Error! ErrorCode=%X", logHeader, res)
		return nil, errors.New("X_Initialize Error!")
	}
	defer C.X_Finalize(handle)

	var cPublicKey [keyLen]C.UCHAR
	cKeyLen := C.UINT32(keyLen)
	res = int(C.X_GenKey(
		handle,
		C.CString(pcUserLabel),
		C.CString(pcUserPin),
		&cPublicKey[0],
		&cKeyLen))
	if res != 0 {
		log.Printf("%s X_GenKey Error! ErrorCode=%X", logHeader, res)
		return nil, errors.New("X_GenKey Error!")
	}
	log.Println(logHeader, "X_GenKey Success!")

	publicKey := C.GoBytes(unsafe.Pointer(&cPublicKey[0]), C.int(keyLen))
	sm2PublicKey, err := x509.ParseSm2PublicKey(publicKey)
	if err != nil {
		return nil, err
	}
	log.Println(logHeader, "Transform to SM2 PublicKey Success!")
	return sm2PublicKey, nil
}
