#pragma once

#ifndef IN
#define IN
#endif

#ifndef OUT
#define OUT
#endif

#if (defined _WIN32) || (defined _WINDOWS_)
#include <Windows.h>
#define STDCALL __stdcall
#else
#include <stdint.h>

#define STDCALL

#ifndef HANDLE
#define HANDLE void *
#endif

#ifndef UCHAR
#define UCHAR unsigned char
#endif

#ifndef CHAR
#define CHAR char
#endif

#ifndef UINT32
#define UINT32 unsigned int
#endif

#ifndef INT32
#define INT32 int
#endif
#endif

#define ERR_SUCCESS								0x0
#define ERR_GEN_RAND							0x00010001
#define ERR_NEED_RETRY							0x00010002
#define ERR_INVALID_PARAMETER					0x00010003
#define ERR_INSUFFICIENT_BUFFER					0x00010004
#define ERR_UNKNOWN_ERROR						0x00010005
#define ERR_NO_MEMORY							0x00010006
#define ERR_UNINITIALIZED						0x00010007
#define ERR_UN_SUPPORTED						0x00010008
#define ERR_INVALIE_CFG							0x00010009

#define ERR_INVALID_SIGNATURE					0x00020001
#define ERR_VERIFY_FAILED						0x00020002
#define ERR_ENCRYPT								0x00020003
#define ERR_GROUP								0x00020004
#define ERR_KDF									0x00020005
#define ERR_GEN_KEY1							0x00020006
#define ERR_GEN_KEY2							0x00020007
#define ERR_SAVE_KEY							0x00020008
#define ERR_READ_KEY							0x00020009
#define ERR_DECRYPT_S1							0x0002000A
#define ERR_DECRYPT_S2							0x0002000B
#define ERR_DECRYPT_S3							0x0002000C
#define ERR_HASH								0x0002000D
#define ERR_PIN									0x0002000E
