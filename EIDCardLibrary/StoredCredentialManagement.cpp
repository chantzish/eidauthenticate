#include <ntstatus.h>
#define WIN32_NO_STATUS
#include <windows.h>
#include <shlobj.h>
#include <Ntsecapi.h>
#include <lm.h>
#include "EidCardLibrary.h"
#include "Tracing.h"
#include "beid.h"

#define CREDENTIALPROVIDER MS_ENH_RSA_AES_PROV
#define CREDENTIALKEYLENGTH 256
#define CREDENTIALCRYPTALG CALG_AES_256
#define CREDENTIAL_LSAPREFIX L"L$_EID_"
#define CREDENTIAL_CONTAINER TEXT("EIDCredential")

#pragma comment(lib,"Crypt32")
#pragma comment(lib,"advapi32")

enum EID_PRIVATE_DATA_TYPE
{
	eidpdtClearText=1,
	eidpdtCrypted = 2,

};

typedef struct _EID_PRIVATE_DATA
{
	EID_PRIVATE_DATA_TYPE dwType;
	USHORT dwCertificatOffset;
	USHORT dwCertificatSize;
	USHORT dwSymetricKeyOffset;
	USHORT dwSymetricKeySize;
	USHORT dwPasswordOffset;
	USHORT dwPasswordSize;
	BYTE Data[sizeof(DWORD)];
} EID_PRIVATE_DATA, *PEID_PRIVATE_DATA;

// level 1
#include "StoredCredentialManagement.h"

// level 2
BOOL SolveChallenge(__in PCCERT_CONTEXT pCertContext, __in LPCTSTR Pin);

BOOL GenerateSymetricKeyAndSaveIt(__in HCRYPTPROV hProv, __in HCRYPTKEY hKey, __out HCRYPTKEY *phKey, __out PBYTE* pSymetricKey, __out USHORT *usSize);
BOOL EncryptPasswordAndSaveIt(__in HCRYPTKEY hKey, __in PWSTR szPassword, __in_opt USHORT dwPasswordLen, __out PBYTE *pEncryptedPassword, __out USHORT *usSize);

BOOL DecryptSymetricKey(__in PCCERT_CONTEXT pCertContext, __in PEID_PRIVATE_DATA Challenge, __in LPCTSTR Pin, __out PBYTE *pSymetricKey, __out USHORT *usSize);
BOOL DecryptPassword(__in PEID_PRIVATE_DATA pEidPrivateData, __in PBYTE pSymetricKey, __in USHORT usSymetricKeySize, __out PWSTR* pszPassword);

// level 3
BOOL RetrievePrivateData(__in DWORD dwRid, __out PEID_PRIVATE_DATA *ppPrivateData);
BOOL StorePrivateData(__in DWORD dwRid, __in_opt PBYTE pbSecret, __in_opt USHORT usSecretSize);
////////////////////////////////////////////////////////////////////////////////
// LEVEL 1
////////////////////////////////////////////////////////////////////////////////

BOOL CanEncryptPassword(__in_opt HCRYPTPROV hProv, __in_opt DWORD dwKeySpec,  __in_opt PCCERT_CONTEXT pCertContext)
{
	HCRYPTKEY hKey = NULL;
	BOOL fEncryptPassword = FALSE, fStatus;
	DWORD dwSize, dwPermissions=0;
	HCRYPTPROV hMyProv = NULL;
	BOOL fCallerFreeProv = FALSE;
	DWORD dwError = 0;
	__try
	{
		EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Enter");
		if (pCertContext)
		{
			if (!CryptAcquireCertificatePrivateKey(pCertContext,0,NULL,&hMyProv,&dwKeySpec,&fCallerFreeProv))
			{
				dwError = GetLastError();
				EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Error 0x%x returned by CryptAcquireCertificatePrivateKey", GetLastError());
				__leave;
			}
		}
		else
		{
			hMyProv = hProv;
		}
		fStatus = CryptGetUserKey(hMyProv, dwKeySpec, &hKey);
		if (!fStatus)
		{
			dwError = GetLastError();
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"CryptGetUserKey 0x%08x",GetLastError());
		}
		dwSize = sizeof(DWORD);
		fStatus = CryptGetKeyParam(hKey, KP_PERMISSIONS, (PBYTE) &dwPermissions, &dwSize, 0);
		if (!fStatus)
		{
			dwError = GetLastError();
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"CryptGetKeyParam 0x%08x",GetLastError());
			__leave;
		}
		if ((!(dwPermissions & CRYPT_ENCRYPT) && !(dwPermissions & CRYPT_DECRYPT)))
		{
			fEncryptPassword = TRUE;
		}
	}
	__finally
	{
		if (hKey)
			CryptDestroyKey(hKey);
		if (fCallerFreeProv)
			CryptReleaseContext(hMyProv,0);
	}
	SetLastError(dwError);
	return fEncryptPassword;
}

BOOL RemoveStoredCredential(__in DWORD dwRid)
{
	return StorePrivateData(dwRid, NULL, 0);
}

BOOL CreateStoredCredential(__in DWORD dwRid,  __in PWSTR szPassword, __in_opt USHORT dwPasswordLen,
							__in PCWSTR szProvider, __in PCWSTR szContainer, __in DWORD dwKeySpec)
{
	BOOL fReturn = FALSE;
	BOOL fStatus;
	DWORD dwSize = 0;
	HCRYPTPROV HCryptProv = NULL;
	HCRYPTKEY hKey = NULL;
	PBYTE pBlob = NULL;
	BOOL fEncryptPassword = FALSE;
	DWORD dwError = 0;
	// save the public key into a file
	// so it can do UpdateCredential
	__try
	{
		EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Enter Rid = %d Container = '%s' Provider = '%s' KeySpec = %d",dwRid, szContainer,szProvider,dwKeySpec);
		// Export public key designated by the container
		fStatus = CryptAcquireContext(&HCryptProv,
				szContainer,
				szProvider,
				PROV_RSA_FULL,
				CRYPT_SILENT);
		if (!fStatus)
		{
			dwError = GetLastError();
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"CryptAcquireContext 0x%08x",GetLastError());
			__leave;
		}
		fStatus = CryptGetUserKey(HCryptProv, dwKeySpec, &hKey);
		if (!fStatus)
		{
			dwError = GetLastError();
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"CryptGetUserKey 0x%08x",GetLastError());
			__leave;
		}

		fStatus = CryptExportKey( hKey, NULL, PUBLICKEYBLOB, 0, NULL, &dwSize);
		if (!fStatus)
		{
			dwError = GetLastError();
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"CryptExportKey 0x%08x",GetLastError());
			__leave;
		}
		pBlob = (PBYTE) malloc(dwSize);
		if (!pBlob)
		{
			dwError = GetLastError();
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"malloc 0x%08x",GetLastError());
			__leave;
		}
		fStatus = CryptExportKey( hKey, NULL, PUBLICKEYBLOB, 0, pBlob, &dwSize);
		if (!fStatus)
		{
			dwError = GetLastError();
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"CryptExportKey 0x%08x",GetLastError());
			__leave;
		}
		fEncryptPassword = CanEncryptPassword(HCryptProv, dwKeySpec, NULL);
		
		// store
		fReturn = UpdateStoredCredentialEx(dwRid, szPassword, dwPasswordLen, pBlob, (USHORT) dwSize, fEncryptPassword);
	}
	__finally
	{
		if (hKey)
			CryptDestroyKey(hKey);
		if (HCryptProv)
			CryptReleaseContext(HCryptProv, 0);
	}
	SetLastError(dwError);
	return fReturn;
}

BOOL UpdateStoredCredential(__in DWORD dwRid, __in PWSTR szPassword, __in_opt USHORT usPasswordLen)
{
	return UpdateStoredCredentialEx(dwRid, szPassword, usPasswordLen, NULL, 0, FALSE);
}

BOOL UpdateStoredCredentialEx(__in DWORD dwRid, __in PWSTR szPassword, __in_opt USHORT usPasswordLen,
							__in_opt PBYTE pPublicKeyBlob, __in_opt USHORT usPublicKeySize, __in_opt BOOL fEncryptPassword)
{
	HCRYPTPROV hProv = NULL;
	BOOL fStatus;
	BOOL fReturn = FALSE;
	HCRYPTKEY hKey = NULL;;
	PBYTE pBlob = NULL;
	HCRYPTKEY hSymetricKey = NULL;
	PBYTE pSymetricKey = NULL;
	USHORT usSymetricKeySize;
	PBYTE pEncryptedPassword = NULL;
	USHORT usEncryptedPasswordSize;
	PEID_PRIVATE_DATA pbSecret = NULL;
	USHORT usSecretSize;
	PEID_PRIVATE_DATA pEidPrivateData = NULL;
	USHORT usPasswordSize;
	DWORD dwError = 0;
	__try
	{
		// get Public Key
		if (pPublicKeyBlob)
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"With public key");
			pBlob = pPublicKeyBlob;
			// dwPermissions = 0  => all access
		}
		else
		{
			// retrieve from previous save
			EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Without public key");
			fEncryptPassword = FALSE;
			fStatus = RetrievePrivateData(dwRid,&pEidPrivateData);
			if (!fStatus)
			{
				dwError = GetLastError();
				__leave;
			}
			pBlob = pEidPrivateData->Data + pEidPrivateData->dwCertificatOffset;
			usPublicKeySize = pEidPrivateData->dwCertificatSize;
			if (pEidPrivateData->dwSymetricKeySize) 
			{
				fEncryptPassword = TRUE;
			}
		}
		usPasswordSize = (usPasswordLen ? usPasswordLen : (USHORT) (wcslen(szPassword) * sizeof(WCHAR)));
		if (!usPasswordSize) fEncryptPassword = FALSE;
		if (fEncryptPassword)
		{
			// crypted
			// import the public key into hKey
			fStatus = CryptAcquireContext(&hProv,CREDENTIAL_CONTAINER,CREDENTIALPROVIDER,PROV_RSA_AES,0);
			if(!fStatus)
			{
				DWORD dwError = GetLastError();
				if (dwError == NTE_BAD_KEYSET)
				{
					fStatus = CryptAcquireContext(&hProv,CREDENTIAL_CONTAINER,CREDENTIALPROVIDER,PROV_RSA_AES,CRYPT_NEWKEYSET);
					dwError = GetLastError();
				}
				if (!fStatus)
				{
					dwError = GetLastError();
					EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"CryptAcquireContext 0x%08x",dwError);
					__leave;
				}
			}
			else
			{
				dwError = GetLastError();
				EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Container already existed !!");
			}
			fStatus = CryptImportKey(hProv,pBlob,usPublicKeySize,0,CRYPT_EXPORTABLE,&hKey);
			if(!fStatus)
			{
				dwError = GetLastError();
				EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"CryptImportKey 0x%08x",GetLastError());
				__leave;
			}
			// create a symetric key which can be used to crypt data and
			// which is saved and protected by the public key
			fStatus = GenerateSymetricKeyAndSaveIt(hProv, hKey, &hSymetricKey, &pSymetricKey, &usSymetricKeySize);
			if(!fStatus)
			{
				dwError = GetLastError();
				EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"GenerateSymetricKeyAndSaveIt");
				__leave;
			}
			// encrypt the password and save it
			fStatus = EncryptPasswordAndSaveIt(hSymetricKey,szPassword,usPasswordLen, &pEncryptedPassword, &usEncryptedPasswordSize);
			if(!fStatus)
			{
				dwError = GetLastError();
				EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"EncryptPasswordAndSaveIt");
				__leave;
			}
			usSecretSize = (USHORT) sizeof(EID_PRIVATE_DATA) + usEncryptedPasswordSize + usSymetricKeySize + usPublicKeySize;
			pbSecret = (PEID_PRIVATE_DATA) malloc(usSecretSize);
			if (!pbSecret)
			{
				dwError = GetLastError();
				EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Error 0x%x returned by malloc", GetLastError());
				__leave;
			}
			// copy data
			pbSecret->dwType = eidpdtCrypted;
			pbSecret->dwCertificatSize = usPublicKeySize;
			pbSecret->dwSymetricKeySize = usSymetricKeySize;
			pbSecret->dwPasswordSize = usEncryptedPasswordSize;
			pbSecret->dwCertificatOffset = 0;
			memcpy(pbSecret->Data + pbSecret->dwCertificatOffset, pBlob, pbSecret->dwCertificatSize);
			pbSecret->dwSymetricKeyOffset = pbSecret->dwCertificatOffset + usPublicKeySize;
			memcpy(pbSecret->Data + pbSecret->dwSymetricKeyOffset, pSymetricKey, pbSecret->dwSymetricKeySize);
			pbSecret->dwPasswordOffset = pbSecret->dwSymetricKeyOffset + usSymetricKeySize;
			memcpy(pbSecret->Data + pbSecret->dwPasswordOffset, pEncryptedPassword, pbSecret->dwPasswordSize);
		}
		else
		{
			// uncrypted
			usSecretSize = (USHORT) sizeof(EID_PRIVATE_DATA) + usPasswordSize + usPublicKeySize;
			pbSecret = (PEID_PRIVATE_DATA) malloc(usSecretSize);
			if (!pbSecret)
			{
				dwError = GetLastError();
				EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Error 0x%x returned by malloc", GetLastError());
				__leave;
			}
			pbSecret->dwType = eidpdtClearText;
			pbSecret->dwCertificatSize = usPublicKeySize;
			pbSecret->dwSymetricKeySize = 0;
			pbSecret->dwPasswordSize = usPasswordSize;
			pbSecret->dwCertificatOffset = 0;
			memcpy(pbSecret->Data + pbSecret->dwCertificatOffset, pBlob, pbSecret->dwCertificatSize);
			pbSecret->dwSymetricKeyOffset = pbSecret->dwCertificatOffset + usPublicKeySize;
			pbSecret->dwPasswordOffset = pbSecret->dwSymetricKeyOffset;
			memcpy(pbSecret->Data + pbSecret->dwPasswordOffset, szPassword, pbSecret->dwPasswordSize);

		}

		// save the data
		if (!StorePrivateData(dwRid, (PBYTE) pbSecret, usSecretSize))
		{
			dwError = GetLastError();
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"StorePrivateData");
			__leave;
		}
		fReturn = TRUE;
	}
	__finally
	{
		if (pEidPrivateData)
			LocalFree(pEidPrivateData);
		if (pSymetricKey)
			free(pSymetricKey);
		if (pEncryptedPassword)
			free(pEncryptedPassword);
		if (pbSecret)
			free(pbSecret);
		if (hSymetricKey)
			CryptDestroyKey(hSymetricKey);
		if (hKey)
			CryptDestroyKey(hKey);
		if (hProv)
		{
			CryptReleaseContext(hProv, 0);
			CryptAcquireContext(&hProv,CREDENTIAL_CONTAINER,CREDENTIALPROVIDER,PROV_RSA_AES,CRYPT_DELETE_KEYSET);
		}
	}
	SetLastError(dwError);
	return fReturn;
}

BOOL RetrieveStoredCredential(__in DWORD dwRid, __in PCCERT_CONTEXT pCertContext, __in LPCTSTR Pin, __out PWSTR *pszPassword)
{
	BOOL fReturn = FALSE;
	PEID_PRIVATE_DATA pEidPrivateData = NULL;
	PBYTE pSymetricKey = NULL;
	USHORT usSymetricKeySize;
	DWORD dwSize;
	PCRYPT_KEY_PROV_INFO pKeyProvInfo = NULL;
	DWORD dwError = 0;
	*pszPassword = NULL;
	EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Enter Rid = %d", dwRid);
	__try
	{
		if (!RetrievePrivateData(dwRid, &pEidPrivateData))
		{
			dwError = GetLastError();
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Error returned by RetrievePrivateData");
			__leave;
		}
		EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Type %d ", pEidPrivateData->dwType);
		switch (pEidPrivateData->dwType)
		{
		case eidpdtClearText:
			// detect Provider name
			dwSize = 0;
			if (!CertGetCertificateContextProperty(pCertContext, CERT_KEY_PROV_INFO_PROP_ID, NULL, &dwSize))
			{
				dwError = GetLastError();
				EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Error 0x%x returned by CertGetCertificateContextProperty", GetLastError());
				__leave;
			}
			pKeyProvInfo = (PCRYPT_KEY_PROV_INFO) malloc(dwSize);
			if (!pKeyProvInfo)
			{
				dwError = GetLastError();
				EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Error 0x%x returned by malloc", GetLastError());
				__leave;
			}
			if (!CertGetCertificateContextProperty(pCertContext, CERT_KEY_PROV_INFO_PROP_ID, (PBYTE) pKeyProvInfo, &dwSize))
			{
				dwError = GetLastError();
				EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Error 0x%x returned by CertGetCertificateContextProperty", GetLastError());
				__leave;
			}
			// authenticate card depending of the CSP
			// belgium identity card
			if (wcscmp(pKeyProvInfo->pwszProvName, WBEIDCSP) == 0)
			{
				if (!SolveBEIDChallenge(pCertContext, Pin))
				{
					dwError = GetLastError();
					EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Error returned by SolveBEIDChallenge");
					__leave;
				}
			}
			// vanilla authentication
			else
			{
				if (!SolveChallenge(pCertContext, Pin))
				{
					dwError = GetLastError();
					EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Error returned by SolveChallenge");
					__leave;
				}
			}
			*pszPassword = (PWSTR) malloc(pEidPrivateData->dwPasswordSize + sizeof(WCHAR));
			if (!*pszPassword)
			{
				dwError = GetLastError();
				EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Error 0x%x returned by malloc", GetLastError());
				__leave;
			}
			memcpy(*pszPassword, pEidPrivateData->Data + pEidPrivateData->dwPasswordOffset, pEidPrivateData->dwPasswordSize);
			*(PWSTR)(((PBYTE)*pszPassword) + pEidPrivateData->dwPasswordSize) = '\0';
			break;
		case eidpdtCrypted:
			if (!DecryptSymetricKey(pCertContext, pEidPrivateData, Pin, &pSymetricKey, &usSymetricKeySize))
			{
				dwError = GetLastError();
				EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Error returned by DecryptSymetricKey");
				__leave;
			}
			if (!DecryptPassword(pEidPrivateData, pSymetricKey, usSymetricKeySize, pszPassword))
			{
				dwError = GetLastError();
				EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Error returned by DecryptPassword");
				__leave;
			}
			break;
		}
		fReturn = TRUE;
	}
	__finally
	{
		if (!fReturn)
		{
			if (*pszPassword)
				free(*pszPassword);
		}
		if (pKeyProvInfo)
			free(pKeyProvInfo);
		if (pSymetricKey)
			free(pSymetricKey);
		if (pEidPrivateData)
			LocalFree(pEidPrivateData);
	}
	SetLastError(dwError);
	return fReturn;
}

////////////////////////////////////////////////////////////////////////////////
// LEVEL 2
////////////////////////////////////////////////////////////////////////////////

BOOL SolveChallenge(__in PCCERT_CONTEXT pCertContext, __in LPCTSTR Pin)
{
	BOOL fReturn = FALSE;
	// check private key
	HCRYPTPROV hProv = NULL, hProvVerif = NULL;
	DWORD dwKeySpec , dwLen;
	BOOL fCallerFreeProv = FALSE;
	HCRYPTKEY hCertKey = NULL;
	HCRYPTHASH hHash = NULL, hHashVerif = NULL;
	LPSTR pbPin = NULL;
	DWORD dwPinLen = 0;
	LPCTSTR sDescription = TEXT("");
	PBYTE Signature = NULL;
	BYTE Challenge[128];
	DWORD dwError = 0;
	EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Enter");
	__try{
		// generate challenge
		if (!CryptAcquireContext(&hProvVerif,NULL,NULL,PROV_RSA_FULL,CRYPT_VERIFYCONTEXT))
		{
			dwError = GetLastError();
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Error 0x%x returned by CryptAcquireContext", GetLastError());
			__leave;
		}
		if (!CryptGenRandom(hProvVerif, sizeof(Challenge), Challenge))
		{
			dwError = GetLastError();
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Error 0x%x returned by CryptGenRandom", GetLastError());
			__leave;
		}

		// create signature
		if (!CryptAcquireCertificatePrivateKey(pCertContext,0,NULL,&hProv,&dwKeySpec,&fCallerFreeProv))
		{
			dwError = GetLastError();
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Error 0x%x returned by CryptAcquireCertificatePrivateKey", GetLastError());
			__leave;
		}
#ifndef UNICODE
		dwPinLen = strlen(Pin) + 1;
		pbPin = (LPSTR) malloc(dwPinLen);
		if (!pbPin)
		{
			dwError = GetLastError();
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Error 0x%x returned by malloc", GetLastError());
			__leave;
		}
		strcpy_s(pbPin, dwPinLen, Pin);
#else
		dwPinLen = wcslen(Pin) + 1;
		pbPin = (LPSTR) malloc(dwPinLen);
		if (!pbPin)
		{
			dwError = GetLastError();
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Error 0x%x returned by malloc", GetLastError());
			__leave;
		}
		if (!WideCharToMultiByte(CP_ACP, 0, Pin, -1, pbPin, dwPinLen, NULL, NULL))
		{
			dwError = GetLastError();
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Error 0x%x returned by WideCharToMultiByte", GetLastError());
			__leave;
		}
#endif
		if (!CryptSetProvParam(hProv, (dwKeySpec == AT_KEYEXCHANGE?PP_KEYEXCHANGE_PIN:PP_SIGNATURE_PIN), (PBYTE) pbPin , 0))
		{
			dwError = GetLastError();
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Error 0x%x returned by CryptSetProvParam - correct PIN ?", GetLastError());
			__leave;
		}
		if (!CryptCreateHash(hProv,CALG_SHA,NULL,0,&hHash))
		{
			dwError = GetLastError();
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Error 0x%x returned by CryptCreateHash", GetLastError());
			__leave;
		}
		if (!CryptSetHashParam(hHash, HP_HASHVAL, Challenge, 0))
		{
			dwError = GetLastError();
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Error 0x%x returned by CryptSetHashParam", GetLastError());
			__leave;
		}
		if (!CryptSignHash(hHash,dwKeySpec, sDescription, 0, NULL, &dwLen))
		{
			dwError = GetLastError();
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Error 0x%x returned by CryptSignHash1", GetLastError());
			__leave;
		}
		Signature = (PBYTE) malloc(dwLen);
		if (!Signature)
		{
			dwError = GetLastError();
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Error 0x%x returned by malloc", GetLastError());
			__leave;
		}
		if (!CryptSignHash(hHash,dwKeySpec, sDescription, 0, Signature, &dwLen))
		{
			dwError = GetLastError();
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Error 0x%x returned by CryptSignHash2", GetLastError());
			__leave;
		}

		// verify signature
	
		if (!CryptImportPublicKeyInfo(hProvVerif, pCertContext->dwCertEncodingType, &(pCertContext->pCertInfo->SubjectPublicKeyInfo),&hCertKey))
		{
			dwError = GetLastError();
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Error 0x%x returned by CryptImportPublicKeyInfo", GetLastError());
			__leave;
		}
		if (!CryptCreateHash(hProvVerif,CALG_SHA,NULL,0,&hHashVerif))
		{
			dwError = GetLastError();
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Error 0x%x returned by CryptCreateHash", GetLastError());
			__leave;
		}
		if (!CryptSetHashParam(hHashVerif, HP_HASHVAL, Challenge, 0))
		{
			dwError = GetLastError();
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Error 0x%x returned by CryptSetHashParam", GetLastError());
			__leave;
		}

		if (!CryptVerifySignature(hHashVerif, Signature, dwLen, hCertKey, sDescription, 0))
		{
			dwError = GetLastError();
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Error 0x%x returned by CryptVerifySignature", GetLastError());
			__leave;
		}
		fReturn = TRUE;
	}
	__finally
	{
		if (Signature)
			free(Signature);
		if (pbPin)
		{
			SecureZeroMemory(pbPin , dwPinLen);
			free(pbPin);
		}
		if (hCertKey)
			CryptDestroyKey(hCertKey);
		if (hHash)
			CryptDestroyHash(hHash);
		if (hHashVerif)
			CryptDestroyHash(hHashVerif);
		if (fCallerFreeProv || hProv) 
			CryptReleaseContext(hProv,0);
		if (hProvVerif)
			CryptReleaseContext(hProvVerif,0);
	}
	SetLastError(dwError);
	return fReturn;
}

BOOL DecryptSymetricKey(__in PCCERT_CONTEXT pCertContext, __in PEID_PRIVATE_DATA pPrivateData, __in LPCTSTR Pin, __out PBYTE *pSymetricKey, __out USHORT *usSize)
{
	BOOL fReturn = FALSE;
	// check private key
	HCRYPTPROV hProv = NULL;
	DWORD dwKeySpec;
	BOOL fCallerFreeProv = FALSE;
	HCRYPTKEY hCertKey = NULL;
	LPSTR pbPin = NULL;
	DWORD dwPinLen = 0;
	HCRYPTKEY hKey = NULL;
	DWORD dwSize;
	DWORD dwBlockLen;
	DWORD dwError = 0;
	EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Enter");
	__try{
		// acquire context on private key
		if (!CryptAcquireCertificatePrivateKey(pCertContext,0,NULL,&hProv,&dwKeySpec,&fCallerFreeProv))
		{
			dwError = GetLastError();
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Error 0x%x returned by CryptAcquireCertificatePrivateKey", GetLastError());
			__leave;
		}
		if (!CryptGetUserKey(hProv, dwKeySpec, &hKey))
		{
			dwError = GetLastError();
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Error 0x%x returned by CryptGetUserKey", GetLastError());
			__leave;
		}
#ifndef UNICODE
		dwPinLen = strlen(Pin) + sizeof(CHAR);
		pbPin = (LPSTR) malloc(dwPinLen);
		if (!pbPin)
		{
			dwError = GetLastError();
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Error 0x%x returned by malloc", GetLastError());
			__leave;
		}
		strcpy_s(pbPin, dwPinLen, Pin);
#else
		dwPinLen = wcslen(Pin) + sizeof(CHAR);
		pbPin = (LPSTR) malloc(dwPinLen);
		if (!pbPin)
		{
			dwError = GetLastError();
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Error 0x%x returned by malloc", GetLastError());
			__leave;
		}
		if (!WideCharToMultiByte(CP_ACP, 0, Pin, -1, pbPin, dwPinLen, NULL, NULL))
		{
			dwError = GetLastError();
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Error 0x%x returned by WideCharToMultiByte", GetLastError());
			__leave;
		}
#endif
		if (!CryptSetProvParam(hProv, (dwKeySpec == AT_KEYEXCHANGE?PP_KEYEXCHANGE_PIN:PP_SIGNATURE_PIN), (PBYTE) pbPin , 0))
		{
			dwError = GetLastError();
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Error 0x%x returned by CryptSetProvParam - correct PIN ?", GetLastError());
			__leave;
		}
		dwSize = sizeof(DWORD);
		if (!CryptGetKeyParam(hKey, KP_BLOCKLEN, (PBYTE) &dwBlockLen, &dwSize, 0))
		{
			dwError = GetLastError();
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Error 0x%x returned by CryptGetKeyParam", GetLastError());
			__leave;
		}
		*pSymetricKey = (PBYTE) malloc(dwBlockLen);
		if (!*pSymetricKey)
		{
			dwError = GetLastError();
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Error 0x%x returned by malloc", GetLastError());
			__leave;
		}
		memcpy(*pSymetricKey, pPrivateData->Data + pPrivateData->dwSymetricKeyOffset, pPrivateData->dwSymetricKeySize);
		dwSize = pPrivateData->dwSymetricKeySize;
		if (!CryptDecrypt(hKey, NULL, TRUE, 0, *pSymetricKey, &dwSize))
		{
			dwError = GetLastError();
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Error 0x%x returned by CryptDecrypt", GetLastError());
			__leave;
		}
		*usSize = (USHORT) dwSize;

		
		fReturn = TRUE;
	}
	__finally
	{
		if (!fReturn)
		{
			if (*pSymetricKey)
			{
				free(*pSymetricKey );
				*pSymetricKey = NULL;
			}
		}
		if (pbPin)
		{
			SecureZeroMemory(pbPin , dwPinLen);
			free(pbPin);
		}
		if (hKey)
			CryptDestroyKey(hKey);
		if (hCertKey)
			CryptDestroyKey(hCertKey);
		if (fCallerFreeProv || hProv) 
			CryptReleaseContext(hProv,0);
	}
	SetLastError(dwError);
	return fReturn;
}





typedef struct _KEY_BLOB {
  BYTE   bType;
  BYTE   bVersion;
  WORD   reserved;
  ALG_ID aiKeyAlg;
  ULONG cb;
  BYTE Data[4096];
} KEY_BLOB;

// create a symetric key which can be used to crypt data and
// which is saved and protected by the public key
BOOL GenerateSymetricKeyAndSaveIt(__in HCRYPTPROV hProv, __in HCRYPTKEY hKey, __out HCRYPTKEY *phKey, __out PBYTE* pSymetricKey, __out USHORT *usSize)
{
	BOOL fReturn = FALSE;
	BOOL fStatus;
	HCRYPTHASH hHash = NULL;
	DWORD dwSize;
	KEY_BLOB bKey;
	DWORD dwError = 0;
	__try
	{
		EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Enter");
		*phKey = NULL;
		dwSize = sizeof(DWORD);
		DWORD dwBlockLen;
		// key is generated here
		bKey.bType = PLAINTEXTKEYBLOB;
		bKey.bVersion = CUR_BLOB_VERSION;
		bKey.reserved = 0;
		bKey.aiKeyAlg = CREDENTIALCRYPTALG;
		bKey.cb = CREDENTIALKEYLENGTH/8;
		fStatus = CryptGenRandom(hProv,bKey.cb,bKey.Data);
		if(!fStatus)
		{
			dwError = GetLastError();
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"CryptGenRandom 0x%08x",GetLastError());
			__leave;
		}
		fStatus = CryptImportKey(hProv,(PBYTE)&bKey,sizeof(KEY_BLOB),NULL,CRYPT_EXPORTABLE,phKey);
		if(!fStatus)
		{
			dwError = GetLastError();
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"CryptImportKey 0x%08x",GetLastError());
			__leave;
		}
		// save
		dwSize = sizeof(DWORD);
		if (!CryptGetKeyParam(*phKey, KP_BLOCKLEN, (PBYTE) &dwBlockLen, &dwSize, 0))
		{
			dwError = GetLastError();
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Error 0x%x returned by CryptGetKeyParam", GetLastError());
			__leave;
		}
		*pSymetricKey = (PBYTE) malloc(dwBlockLen);
		if (!*pSymetricKey)
		{
			dwError = GetLastError();
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Error 0x%x returned by malloc", GetLastError());
			__leave;
		}
		memcpy(*pSymetricKey, bKey.Data, CREDENTIALKEYLENGTH/8);
		dwSize = CREDENTIALKEYLENGTH/8;
		fStatus = CryptEncrypt(hKey, hHash,TRUE,0,*pSymetricKey,&dwSize, dwBlockLen);
		if(!fStatus)
		{
			dwError = GetLastError();
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"CryptEncrypt 0x%08x",GetLastError());
			__leave;
		}
		*usSize = (USHORT) dwSize;
		// bKey is know encrypted
		
		fReturn = TRUE;
	}
	__finally
	{
		if (!fReturn)
		{
			if (*pSymetricKey)
				free(*pSymetricKey);
			if (*phKey)
			{
				CryptDestroyKey(*phKey);
			}
		}
		if (hHash)
			CryptDestroyHash(hHash);
	}
	SetLastError(dwError);
	return fReturn;
}

BOOL EncryptPasswordAndSaveIt(__in HCRYPTKEY hKey, __in PWSTR szPassword, __in_opt USHORT dwPasswordLen, __out PBYTE *pEncryptedPassword, __out USHORT *usSize)
{
	BOOL fReturn = FALSE, fStatus;
	DWORD dwPasswordSize, dwSize, dwBlockLen, dwEncryptedSize;
	DWORD dwRoundNumber;
	DWORD dwError = 0;
	__try
	{
		EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Enter");
		dwPasswordSize = (dwPasswordLen?dwPasswordLen:wcslen(szPassword)* sizeof(WCHAR));
		dwSize = sizeof(DWORD);
		if (!CryptGetKeyParam(hKey, KP_BLOCKLEN, (PBYTE) &dwBlockLen, &dwSize, 0))
		{
			dwError = GetLastError();
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Error 0x%x returned by CryptGetKeyParam", GetLastError());
			__leave;
		}
		// block size = 256             100 => 1     256 => 1      257  => 2
		dwRoundNumber = ((DWORD)(dwPasswordSize/dwBlockLen)) + ((dwPasswordSize%dwBlockLen) ? 1 : 0);
		*pEncryptedPassword = (PBYTE) malloc(dwRoundNumber * dwBlockLen);
		if (!*pEncryptedPassword)
		{
			dwError = GetLastError();
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"malloc 0x%08x",GetLastError());
			__leave;
		}	
		memset(*pEncryptedPassword, 0, dwRoundNumber * dwBlockLen);
		memcpy(*pEncryptedPassword, szPassword, dwPasswordSize);
		
		dwEncryptedSize = 0;
		for (DWORD dwI = 0; dwI < dwRoundNumber; dwI++)
		{
			dwEncryptedSize = (dwI == dwRoundNumber-1 ? dwPasswordSize%dwBlockLen : dwBlockLen);
			fStatus = CryptEncrypt(hKey, NULL,(dwI == dwRoundNumber-1 ? TRUE:FALSE),0,
						*pEncryptedPassword + dwI * dwBlockLen,
						&dwEncryptedSize, dwBlockLen);
			if(!fStatus)
			{
				dwError = GetLastError();
				EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"CryptEncrypt 0x%08x",GetLastError());
				__leave;
			}
		}
		*usSize = (USHORT) ((dwRoundNumber -1 ) * dwBlockLen + dwEncryptedSize);
		// szPassword is know encrypted

		fReturn = TRUE;
	}
	__finally
	{
		if (!fReturn)
		{
			if (*pEncryptedPassword)
				free(*pEncryptedPassword);
		}
	}
	SetLastError(dwError);
	return fReturn;
}



BOOL DecryptPassword(__in PEID_PRIVATE_DATA pEidPrivateData, __in PBYTE pSymetricKey, __in USHORT usSymetricKeySize, __out PWSTR* pszPassword)
{
	BOOL fReturn = FALSE, fStatus;
	DWORD dwSize;
	HCRYPTPROV hProv = NULL;
	HCRYPTKEY hKey = NULL;
	KEY_BLOB bKey;
	*pszPassword = NULL;
	DWORD dwBlockLen;
	DWORD dwRoundNumber;
	DWORD dwError = 0;
	__try
	{
		// read the encrypted password
		EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Enter");
		// key is generated here
		bKey.bType = PLAINTEXTKEYBLOB;
		bKey.bVersion = CUR_BLOB_VERSION;
		bKey.reserved = 0;
		bKey.aiKeyAlg = CREDENTIALCRYPTALG;
		bKey.cb = usSymetricKeySize;
		memcpy(bKey.Data, pSymetricKey, usSymetricKeySize);
		// import the aes key
		fStatus = CryptAcquireContext(&hProv,CREDENTIAL_CONTAINER,CREDENTIALPROVIDER,PROV_RSA_AES,0);
		if(!fStatus)
		{
			dwError = GetLastError();
			if (dwError == NTE_BAD_KEYSET)
			{
				fStatus = CryptAcquireContext(&hProv,CREDENTIAL_CONTAINER,CREDENTIALPROVIDER,PROV_RSA_AES,CRYPT_NEWKEYSET);
				dwError = GetLastError();
			}
			if (!fStatus)
			{
				EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"CryptAcquireContext 0x%08x",dwError);
				__leave;
			}
		}
		else
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Container already existed !!");
		}
		fStatus = CryptImportKey(hProv,(PBYTE) &bKey,usSymetricKeySize,0,CRYPT_EXPORTABLE,&hKey);
		if(!fStatus)
		{
			dwError = GetLastError();
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"CryptImportKey 0x%08x",GetLastError());
			__leave;
		}
		// decode it
		dwSize = sizeof(DWORD);
		if (!CryptGetKeyParam(hKey, KP_BLOCKLEN, (PBYTE) &dwBlockLen, &dwSize, 0))
		{
			dwError = GetLastError();
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Error 0x%x returned by CryptGetKeyParam", GetLastError());
			__leave;
		}
		dwRoundNumber = (DWORD)(pEidPrivateData->dwPasswordSize / dwBlockLen) + 
			((pEidPrivateData->dwPasswordSize % dwBlockLen) ? 1 : 0);
		*pszPassword = (PWSTR) malloc(dwRoundNumber *  dwBlockLen + sizeof(WCHAR));
		if (!*pszPassword)
		{
			dwError = GetLastError();
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"malloc 0x%08x", GetLastError());
			__leave;
		}
		memcpy(*pszPassword, pEidPrivateData->Data + pEidPrivateData->dwPasswordOffset, pEidPrivateData->dwPasswordSize);

		for (DWORD dwI = 0; dwI < dwRoundNumber ; dwI++)
		{
			dwSize = (dwI == dwRoundNumber -1 ? pEidPrivateData->dwPasswordSize%dwBlockLen : dwBlockLen);
			fStatus = CryptDecrypt(hKey, NULL,(dwI == dwRoundNumber -1 ?TRUE:FALSE),0,
				((PBYTE) *pszPassword) + dwI * dwBlockLen,&dwSize);
			if(!fStatus)
			{
				dwError = GetLastError();
				EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"CryptDecrypt 0x%08x",GetLastError());
				__leave;
			}
		}
		(*pszPassword)[((dwRoundNumber-1) * dwBlockLen + dwSize)/sizeof(WCHAR)] = '\0';
		fReturn = TRUE;
	}
	__finally
	{
		if (!fReturn)
		{
			if (*pszPassword) 
				free(*pszPassword);
		}
		if (hKey)
			CryptDestroyKey(hKey);
		if (hProv)
		{
			CryptReleaseContext(hProv, 0);
			CryptAcquireContext(&hProv,CREDENTIAL_CONTAINER,CREDENTIALPROVIDER,PROV_RSA_AES,CRYPT_DELETE_KEYSET);
		}
	}
	SetLastError(dwError);
	return fReturn;
}


////////////////////////////////////////////////////////////////////////////////
// LEVEL 3
////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////
// Private Data Storage
////////////////////////////////////////////////////////

extern "C" 
{
	//http://msdn.microsoft.com/en-us/library/cc234344(PROT.10).aspx
	NTSTATUS NTAPI LsaSetSecurityObject (LSA_HANDLE SecretHandle, SECURITY_INFORMATION si, PSECURITY_DESCRIPTOR pSD); 
	//http://msdn.microsoft.com/en-us/library/cc234343(PROT.10).aspx
	NTSTATUS NTAPI LsaQuerySecurityObject (LSA_HANDLE SecretHandle, SECURITY_INFORMATION si, PSECURITY_DESCRIPTOR *ppSD); 
	//http://msdn.microsoft.com/en-us/library/cc234362(PROT.10).aspx
	NTSTATUS NTAPI LsaCreateSecret(LSA_HANDLE PolicyHandle, PUNICODE_STRING SecretName, ACCESS_MASK DesiredAccess,LSA_HANDLE* SecretHandle);
	//http://msdn.microsoft.com/en-us/library/cc234363(PROT.10).aspx
	NTSTATUS NTAPI LsaOpenSecret(LSA_HANDLE PolicyHandle, PUNICODE_STRING SecretName, ACCESS_MASK DesiredAccess, LSA_HANDLE* SecretHandle);
	//http://msdn.microsoft.com/en-us/library/cc234364(PROT.10).aspx
	NTSTATUS NTAPI LsaSetSecret(LSA_HANDLE SecretHandle,PUNICODE_STRING EncryptedCurrentValue,PUNICODE_STRING EncryptedOldValue);
	//http://msdn.microsoft.com/en-us/library/cc234365(PROT.10).aspx
	NTSTATUS NTAPI LsaQuerySecret(LSA_HANDLE SecretHandle,PUNICODE_STRING* EncryptedCurrentValue, PLARGE_INTEGER CurrentValueSetTime,
	  PUNICODE_STRING* EncryptedOldValue, PLARGE_INTEGER OldValueSetTime);
}

NTSTATUS MyLsaStorePrivateData(
    __in LSA_HANDLE PolicyHandle,
    __in PLSA_UNICODE_STRING KeyName,
    __in_opt PLSA_UNICODE_STRING PrivateData
    )
{
	LSA_HANDLE SecretHandle;
	NTSTATUS status = LsaOpenSecret(PolicyHandle, KeyName, 0, &SecretHandle);
	if (status == STATUS_OBJECT_NAME_NOT_FOUND)
	{
		status = LsaCreateSecret(PolicyHandle, KeyName,  0, &SecretHandle);
	}
	if (status != STATUS_SUCCESS)
	{
		SetLastError(LsaNtStatusToWinError(status));
		return status;
	}
	status = LsaSetSecret(SecretHandle, PrivateData, NULL);
	LsaClose(SecretHandle);
	return status;
}

NTSTATUS MyLsaRetrievePrivateData(
    __in LSA_HANDLE PolicyHandle,
    __in PLSA_UNICODE_STRING KeyName,
    __out PLSA_UNICODE_STRING * PrivateData
    )
{
	LSA_HANDLE SecretHandle;
	LARGE_INTEGER CurrentValueSetTime;
	LARGE_INTEGER OldValueSetTime;
	NTSTATUS status = LsaOpenSecret(PolicyHandle, KeyName, 0, &SecretHandle);
	if (status != STATUS_SUCCESS)
	{
		SetLastError(LsaNtStatusToWinError(status));
		return status;
	}
	status = LsaQuerySecret(SecretHandle,PrivateData,&CurrentValueSetTime,NULL,&OldValueSetTime);
	LsaClose(SecretHandle);
	return status;
}

BOOL StorePrivateData(__in DWORD dwRid, __in_opt PBYTE pbSecret, __in_opt USHORT usSecretSize)
{

    LSA_OBJECT_ATTRIBUTES ObjectAttributes;
    LSA_HANDLE LsaPolicyHandle = NULL;

    LSA_UNICODE_STRING lusSecretName;
    LSA_UNICODE_STRING lusSecretData;
	WCHAR szLsaKeyName[256];

    NTSTATUS ntsResult = STATUS_SUCCESS;

    //  Object attributes are reserved, so initialize to zeros.
    ZeroMemory(&ObjectAttributes, sizeof(ObjectAttributes));

    //  Get a handle to the Policy object.
    ntsResult = LsaOpenPolicy(
        NULL,    // local machine
        &ObjectAttributes, 
        POLICY_CREATE_SECRET,
        &LsaPolicyHandle);

    if( STATUS_SUCCESS != ntsResult )
    {
        //  An error occurred. Display it as a win32 error code.
        EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Error 0x%x returned by LsaOpenPolicy", ntsResult);
		SetLastError(LsaNtStatusToWinError(ntsResult));
        return FALSE;
    } 

    //  Initialize an LSA_UNICODE_STRING for the name of the
	wsprintf(szLsaKeyName, L"%s_%08X", CREDENTIAL_LSAPREFIX, dwRid);
	
    lusSecretName.Buffer = szLsaKeyName;
    lusSecretName.Length = (USHORT) wcslen(szLsaKeyName)* sizeof(WCHAR);
    lusSecretName.MaximumLength = lusSecretName.Length;
    //  If the pwszSecret parameter is NULL, then clear the secret.
    if( NULL == pbSecret )
    {
        EIDCardLibraryTrace(WINEVENT_LEVEL_INFO,L"Clearing");
		ntsResult = LsaStorePrivateData(
            LsaPolicyHandle,
            &lusSecretName,
            NULL);
    }
    else
    {
        EIDCardLibraryTrace(WINEVENT_LEVEL_INFO,L"Setting");
		//  Initialize an LSA_UNICODE_STRING for the value
        //  of the private data. 
        lusSecretData.Buffer = (PWSTR) pbSecret;
        lusSecretData.Length = usSecretSize;
        lusSecretData.MaximumLength = usSecretSize;
        ntsResult = LsaStorePrivateData(
            LsaPolicyHandle,
            &lusSecretName,
            &lusSecretData);
    }

    LsaClose(LsaPolicyHandle);
    if( STATUS_SUCCESS != ntsResult )
    {
        //  An error occurred. Display it as a win32 error code.
        EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Error 0x%x returned by LsaStorePrivateData", ntsResult);
		SetLastError(LsaNtStatusToWinError(ntsResult));
        return FALSE;
    } 
    return TRUE;

}

BOOL RetrievePrivateData(__in DWORD dwRid, __out PEID_PRIVATE_DATA *ppPrivateData)
{
	LSA_OBJECT_ATTRIBUTES ObjectAttributes;
    LSA_HANDLE LsaPolicyHandle = NULL;
	PLSA_UNICODE_STRING pData = NULL;
    LSA_UNICODE_STRING lusSecretName;
	WCHAR szLsaKeyName[256];
	NTSTATUS ntsResult = STATUS_SUCCESS;
    //  Object attributes are reserved, so initialize to zeros.
    ZeroMemory(&ObjectAttributes, sizeof(ObjectAttributes));

    //  Get a handle to the Policy object.
    ntsResult = LsaOpenPolicy(
        NULL,    // local machine
        &ObjectAttributes, 
        POLICY_GET_PRIVATE_INFORMATION,
        &LsaPolicyHandle);

    if( STATUS_SUCCESS != ntsResult )
    {
        //  An error occurred. Display it as a win32 error code.
        EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Error 0x%x returned by LsaOpenPolicy", ntsResult);
		SetLastError(LsaNtStatusToWinError(ntsResult));
        return FALSE;
    } 

    //  Initialize an LSA_UNICODE_STRING for the name of the
    //  private data ("DefaultPassword").
	wsprintf(szLsaKeyName, L"%s_%08X", CREDENTIAL_LSAPREFIX, dwRid);
	
    lusSecretName.Buffer = szLsaKeyName;
    lusSecretName.Length = (USHORT) wcslen(szLsaKeyName)* sizeof(WCHAR);
    lusSecretName.MaximumLength = lusSecretName.Length;
    
	EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Reading");
    ntsResult = LsaRetrievePrivateData(LsaPolicyHandle,&lusSecretName,&pData);
	
    LsaClose(LsaPolicyHandle);
    if( STATUS_SUCCESS != ntsResult )
    {
        EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Error 0x%x returned by LsaRetrievePrivateData", ntsResult);
		SetLastError(LsaNtStatusToWinError(ntsResult));
        return FALSE;
    } 
	*ppPrivateData = (PEID_PRIVATE_DATA) LocalAlloc(0, pData->Length);
	if (!*ppPrivateData)
	{
		EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Error 0x%x returned by LocalAlloc", GetLastError());
        return FALSE;
	}
	memcpy(*ppPrivateData, pData->Buffer, pData->Length);
	LsaFreeMemory(pData);
	return TRUE;
}

BOOL HasStoredCredential(__in DWORD dwRid)
{
	BOOL fReturn = FALSE;
	PEID_PRIVATE_DATA pSecret;
	if (RetrievePrivateData(dwRid, &pSecret))
	{
		fReturn = TRUE;
		LocalFree(pSecret);
	}
	EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"%s",(fReturn?L"TRUE":L"FALSE"));
	return fReturn;
}
//////////////////////////////////////////////////////////////

