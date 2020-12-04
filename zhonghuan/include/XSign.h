#ifndef X_SIGN_API_H_H_
#define X_SIGN_API_H_H_

#include "XDef.h"

#ifdef __cplusplus
extern "C"
{
#endif

	/**
	* 获取接口版本号
	* @param  {UINT32*} pnVersion : 返回版本信息
	* @return {UINT32}            : 0成功，其他失败
	*/
	UINT32 STDCALL X_GetVersion(UINT32 *pnVersion);

	/**
	* 初始化。调用其他密钥相关算法之前，先调用此接口，用于初始化调用后台的信息接口。
	* @param  {CHAR*} pcCfg       : 配置文件内容，{"Remote":false,"Asn1":true,"Path":"","Url":"http://127.0.0.1/key","AppId":"1","AppPwd":"12345678","License":"488351a9861e7ed695f3cdb9a3e7909e"}
	* @param  {HANDLE*} phContext : 返回的句柄
	* @return {UINT32}            : 0成功，其他失败
	*/
	UINT32 STDCALL X_Initialize(CHAR *pcCfg, HANDLE *phContext);

	/**
	* 反初始化
	* @param  {HANDLE} hContext : 句柄，调用X_Initialize接口获取
	* @return {UINT32}          : 0成功，其他失败
	*/
	UINT32 STDCALL X_Finalize(HANDLE hContext);

	/**
	* 产生密钥对
	* @param  {HANDLE} hContext         : 句柄，调用X_Initialize接口获取
	* @param  {CHAR*} pcUserLabel       : 用户标识
	* @param  {CHAR*} pcUserPin         : 用户PIN码
	* @param  {UCHAR*} pucPublicKey     : 公钥信息，如果配置Asn1为true，则返回asn1结构，否则返回X||Y
	* @param  {UINT32*} puiPublicKeyLen : 公钥长度
	* @return {UINT32}                  : 0成功，其他失败
	*/
	UINT32 STDCALL X_GenKey(HANDLE hContext, CHAR *pcUserLabel, CHAR *pcUserPin, UCHAR *pucPublicKey, UINT32 *puiPublicKeyLen);

	/**
	* 删除密钥对
	* @param  {HANDLE} hContext         : 句柄，调用X_Initialize接口获取
	* @param  {CHAR*} pcUserLabel       : 用户标识
	* @return {UINT32}                  : 0成功，其他失败
	*/
	UINT32 STDCALL X_DelKey(HANDLE hContext, CHAR *pcUserLabel);

	/**
	* 获取公钥
	* @param  {HANDLE} hContext         : 句柄，调用X_Initialize接口获取
	* @param  {CHAR*} pcUserLabel       : 用户标识
	* @param  {UCHAR*} pucPublicKey     : 公钥信息，如果配置Asn1为true，则返回asn1结构，否则返回X||Y
	* @param  {UINT32*} puiPublicKeyLen : 公钥长度
	* @return {UINT32}                  : 0成功，其他失败
	*/
	UINT32 STDCALL X_GetPublicKey(HANDLE hContext, CHAR *pcUserLabel, UCHAR *pucPublicKey, UINT32 *puiPublicKeyLen);

	/**
	* SM3摘要
	* @param  {UCHAR*} pucData     : 原文
	* @param  {UINT32} uiDataLen   : 原文长度
	* @param  {UCHAR*} pucHash     : 摘要值
	* @param  {UINT32*} puiHashLen : 摘要值长度，正常为32
	* @return {UINT32}             : 0成功，其他失败
	*/
	UINT32 STDCALL X_Hash(UCHAR *pucData, UINT32 uiDataLen, UCHAR *pucHash, UINT32 *puiHashLen);

	/**
	* 数字签名
	* @param  {HANDLE} hContext         : 句柄，调用X_Initialize接口获取
	* @param  {CHAR*} pcUserLabel       : 用户标识
	* @param  {CHAR*} pcUserPin         : 用户PIN码
	* @param  {UCHAR*} pucData          : 签名原文
	* @param  {UINT32} uiDataLen        : 签名原文长度
	* @param  {UCHAR*} pucSignValue     : 签名值，如果配置Asn1为true，则返回asn1结构，否则返回X||Y
	* @param  {UINT32*} puiSignValueLen : 签名值长度
	* @return {UINT32}                  : 0成功，其他失败
	*/
	UINT32 STDCALL X_Sign(HANDLE hContext, CHAR *pcUserLabel, CHAR *pcUserPin, UCHAR *pucData, UINT32 uiDataLen, UCHAR *pucSignValue, UINT32 *puiSignValueLen);

	/**
	* 验证签名
	* @param  {UCHAR*} pucData        : 签名原文
	* @param  {UINT32} uiDataLen      : 签名原文长度
	* @param  {UCHAR*} pucPublicKey   : 公钥
	* @param  {UINT32} uiPublicKeyLen : 公钥长度
	* @param  {UCHAR*} pucSignValue   : 签名值
	* @param  {UINT32} uiSignValueLen : 签名值长度
	* @return {UINT32}                 : 0成功，其他失败
	*/
	UINT32 STDCALL X_Verify(UCHAR *pucData, UINT32 uiDataLen, UCHAR *pucPublicKey, UINT32 uiPublicKeyLen, UCHAR *pucSignValue, UINT32 uiSignValueLen);

	/**
	* 非对称加密
	* @param  {UCHAR*} pucPublicKey   : 公钥
	* @param  {UINT32} uiPublicKeyLen : 公钥长度
	* @param  {UCHAR*} pucData        : 明文
	* @param  {UINT32} uiDataLen      : 明文长度
	* @param  {UCHAR*} pucEncData     : 密文，格式为C1||C3||C2
	* @param  {UINT32*} puiEncDataLen : 密文长度
	* @return {UINT32}                : 0成功，其他失败
	*/
	UINT32 STDCALL X_AsymmEncrypt(UCHAR *pucPublicKey, UINT32 uiPublicKeyLen, UCHAR *pucData, UINT32 uiDataLen, UCHAR *pucEncData, UINT32 *puiEncDataLen);

	/**
	* 非对称解密
	* @param  {HANDLE} hContext     : 句柄，调用X_Initialize接口获取
	* @param  {CHAR*} pcUserLabel   : 用户标识
	* @param  {CHAR*} pcUserPin     : 用户PIN码
	* @param  {UCHAR*} pucEncData   : 密文
	* @param  {UINT32} uiEncDataLen : 密文长度
	* @param  {UCHAR*} pucData      : 明文
	* @param  {UINT32*} puiDataLen  : 明文长度
	* @return {UINT32}              : 0成功，其他失败
	*/
	UINT32 STDCALL X_AsymmDecrypt(HANDLE hContext, CHAR *pcUserLabel, CHAR *pcUserPin, UCHAR *pucEncData, UINT32 uiEncDataLen, UCHAR *pucData, UINT32 *puiDataLen);

#ifdef __cplusplus
}
#endif

#endif //X_SIGN_API_H_H_