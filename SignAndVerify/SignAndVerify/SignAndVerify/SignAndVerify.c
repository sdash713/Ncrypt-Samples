// SignAndVerify.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <stdio.h>
#include <windows.h>
#include <bcrypt.h>
#include <ncrypt.h>


#define CHECK_ERROR if(status != ERROR_SUCCESS){ printf("Line:- %d Failed with error %X \n", __LINE__, status);}


void  main()
{
	SECURITY_STATUS status = ERROR_SUCCESS;
	NCRYPT_PROV_HANDLE providerHandle = 0;
	NCRYPT_KEY_HANDLE  rsaKey = 0;
	DWORD keySize = 2048;


	status = NCryptOpenStorageProvider(&providerHandle, MS_KEY_STORAGE_PROVIDER, 0);
	CHECK_ERROR;

	status = NCryptCreatePersistedKey(providerHandle, &rsaKey, NCRYPT_RSA_ALGORITHM, L"rsa2048key", 0, NCRYPT_OVERWRITE_KEY_FLAG);
	CHECK_ERROR;

	status = NCryptSetProperty(rsaKey, NCRYPT_LENGTH_PROPERTY, (PBYTE)&keySize, sizeof(DWORD), 0);
	CHECK_ERROR;

	status = NCryptFinalizeKey(rsaKey, 0);
	CHECK_ERROR;


}
