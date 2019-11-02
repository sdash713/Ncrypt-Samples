/*****************************************************************************************************
*Copyright 2019 Santosh Kumar Dash
*
*Licensed under the Apache License, Version 2.0 (the "License");
*you may not use this file except in compliance with the License.
*You may obtain a copy of the License at
*
*	http://www.apache.org/licenses/LICENSE-2.0
*
*Unless required by applicable law or agreed to in writing, software
*distributed under the License is distributed on an "AS IS" BASIS,
*WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
*See the License for the specific language governing permissions and
*limitations under the License.
*
*********************************************************************************************************/
#include <stdio.h>
#include <windows.h>
#include <ntstatus.h>
#include <bcrypt.h>
#include <ncrypt.h>


#define CHECK_ERROR if(status != ERROR_SUCCESS){ printf("Line:- %d Failed with error %X \n", __LINE__, status);}

void hexDump(const char* description, const void* address, const int length) {
	int iterator = 0;
	unsigned char buffer[17];
	const unsigned char* printableCharacter = (const unsigned char*)address;

	if (description != NULL)
		printf("%s:\n", description);

	if (length == 0 || address == NULL) {
		printf("  No data\n");
		return;
	}
	if (length < 0) {
		printf("  Invalid Length: %i\n", length);
		return;
	}

	// Process data byte by byte.
	for (iterator = 0; iterator < length; iterator++) {
		// One line 16 characters

		if ((iterator % 16) == 0) {
			// Don't print ASCII for the zeroth line.
			if (iterator != 0)
				printf("  %s\n", buffer);

			// Print the offset.
			printf("  %04x ", iterator);
		}

		// Now the hex code for the specific character.
		printf(" %02x", printableCharacter[iterator]);

		// And store a printable ASCII character for later.
		if ((printableCharacter[iterator] < 0x20) || (printableCharacter[iterator] > 0x7e))
			buffer[iterator % 16] = '.';
		else
			buffer[iterator % 16] = printableCharacter[iterator];
		buffer[(iterator % 16) + 1] = '\0';
	}

	// Pad with space in last line if not exactly 16 characters.
	while ((iterator % 16) != 0) {
		printf("   ");
		iterator++;
	}

	// And print the final ASCII bit.
	printf("  %s\n", buffer);
}


void hashOfData(LPWSTR data, BYTE **hash, DWORD *hashLength)
{
	NTSTATUS status = STATUS_SUCCESS;
	/* Use bcrypt create hash functions to create the hash of the data */
	BCRYPT_ALG_HANDLE hashAlgHandle = 0;
	BCRYPT_HASH_HANDLE hashHandle = 0;
	DWORD  cbResult = 0;

	status = BCryptOpenAlgorithmProvider(&hashAlgHandle, BCRYPT_SHA256_ALGORITHM, NULL, 0);
	CHECK_ERROR;
	status = BCryptGetProperty(hashAlgHandle, BCRYPT_HASH_LENGTH, hashLength, sizeof(DWORD), &cbResult, 0);
	CHECK_ERROR;
	*hash = calloc(*hashLength, 1);
	if (*hash == NULL)
	{
		printf("Memory allocation failed.\n");
		exit(-1);
	}
	status = BCryptHash(hashAlgHandle, NULL, 0, data, wcslen(data) * sizeof(WCHAR), *hash, *hashLength);
	CHECK_ERROR;

	status = BCryptCloseAlgorithmProvider(hashAlgHandle, 0);
	CHECK_ERROR;

}


void  main()
{
	SECURITY_STATUS status = ERROR_SUCCESS;
	NCRYPT_PROV_HANDLE providerHandle = 0;
	NCRYPT_KEY_HANDLE  rsaKey = 0;
	DWORD keySize = 2048;
	BYTE* hash = NULL;
	DWORD hashLength = 0;
	BCRYPT_PKCS1_PADDING_INFO pkcs1Padding;
	BYTE* signature = 0;
	DWORD signatureLength = 0;


	status = NCryptOpenStorageProvider(&providerHandle, MS_KEY_STORAGE_PROVIDER, 0);
	CHECK_ERROR;

	status = NCryptCreatePersistedKey(providerHandle, &rsaKey, NCRYPT_RSA_ALGORITHM, L"rsa2048key", 0, NCRYPT_OVERWRITE_KEY_FLAG);
	CHECK_ERROR;

	status = NCryptSetProperty(rsaKey, NCRYPT_LENGTH_PROPERTY, (PBYTE)&keySize, sizeof(DWORD), 0);
	CHECK_ERROR;

	status = NCryptFinalizeKey(rsaKey, 0);
	CHECK_ERROR;

	/* Create the hash of the data */
	hashOfData(L"Hello World!", &hash, &hashLength);
	hexDump("Hash:-", hash, hashLength);
	pkcs1Padding.pszAlgId = BCRYPT_SHA256_ALGORITHM;
	status = NCryptSignHash(rsaKey, &pkcs1Padding, hash, hashLength, NULL, 0, &signatureLength, BCRYPT_PAD_PKCS1);
	CHECK_ERROR;

	signature = calloc(signatureLength, 1);
	if (signature == NULL)
	{
		printf("Memory allocation failed.\n");
		exit(-1);
	}
	status = NCryptSignHash(rsaKey, &pkcs1Padding, hash, hashLength, signature, signatureLength, &signatureLength, BCRYPT_PAD_PKCS1);
	CHECK_ERROR;

	hexDump("Signature:-", signature, signatureLength);


	/* Now verify the signature */
	status = NCryptVerifySignature(rsaKey, &pkcs1Padding, hash, hashLength, signature, signatureLength, BCRYPT_PAD_PKCS1);
	if (status == ERROR_SUCCESS)
	{
		printf("\n\nSignature verification success.\n");
	}
	else
	{
		printf("Signature verification failed.\n");
	}
}
