/*	EID Authentication
    Copyright (C) 2009 Vincent Le Toux

    This library is free software; you can redistribute it and/or
    modify it under the terms of the GNU Lesser General Public
    License version 2.1 as published by the Free Software Foundation.

    This library is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
    Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public
    License along with this library; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/

#include <windows.h>
#include <tchar.h>
#include "EIDCardLibrary.h"
#include "Tracing.h"
#include "GPO.h"
#include "beid.h"

#pragma comment(lib,"Crypt32")

LPTSTR GetUserNameFromCertificate(__in PCCERT_CONTEXT pCertContext)
{
	LPTSTR szReturnedName = NULL;
	DWORD dwSize;
	BOOL fReturn = FALSE;
	PCRYPT_KEY_PROV_INFO pKeyProvInfo = NULL;
	__try
	{
		// get the subject details for the cert
		dwSize = CertGetNameString(pCertContext,CERT_NAME_SIMPLE_DISPLAY_TYPE,0,NULL,NULL,0);
		if (!dwSize)
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"CertGetNameString error = %d",GetLastError());
			__leave;
		}
		szReturnedName = (LPTSTR) malloc(dwSize*sizeof(TCHAR));
		if (!szReturnedName) 
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"malloc error = %d",GetLastError());
			__leave;
		}
		dwSize = CertGetNameString(pCertContext,CERT_NAME_SIMPLE_DISPLAY_TYPE,0,NULL,szReturnedName,dwSize);
		if (!dwSize)
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"CertGetNameString error = %d",GetLastError());
			__leave;
		}
		// remove any weird characters
		// (else we can not match an existing username because it is not accepted as valid username by windows)
		for (DWORD i = 0; i<dwSize; i++)
		{
			TCHAR cChar = szReturnedName[i];
			if (cChar < 13 && cChar >0)
			{
				szReturnedName[i] = '_';
			}
			if (cChar == '\\' || cChar == ':' || cChar == '+' ||
				cChar == '/' || cChar == ';' || cChar == '=' ||
				cChar == '[' || cChar == '|' || cChar == ',' ||
				cChar == ']' || cChar == '<' || cChar == '?' ||
				cChar == '"' || cChar == '>' || cChar == '*')
			{
				szReturnedName[i] = '_';
			}

		}
			// check if it is a Belgian Eid card to drop the '(Authentication)'
		dwSize = 0;
		
		if (!CertGetCertificateContextProperty(pCertContext, CERT_KEY_PROV_INFO_PROP_ID, NULL, &dwSize))
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Error 0x%x returned by CertGetCertificateContextProperty", GetLastError());
			__leave;
		}
		pKeyProvInfo = (PCRYPT_KEY_PROV_INFO) malloc(dwSize);
		if (!pKeyProvInfo)
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Error 0x%x returned by malloc", GetLastError());
			__leave;
		}
		if (!CertGetCertificateContextProperty(pCertContext, CERT_KEY_PROV_INFO_PROP_ID, (PBYTE) pKeyProvInfo, &dwSize))
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Error 0x%x returned by CertGetCertificateContextProperty", GetLastError());
			__leave;
		}
		if (_tcscmp(pKeyProvInfo->pwszProvName, TBEIDCSP) == 0)
		{
			szReturnedName[_tcslen(szReturnedName) - 17] = '\0';
		}
		// truncate it to max 20 char
		if (_tcsclen(szReturnedName) >= 21) 
			szReturnedName[20]=0;
		fReturn = TRUE;

	}
	__finally
	{
		if (pKeyProvInfo)
			free(pKeyProvInfo);
		if (!fReturn)
		{
			if (szReturnedName)
			{
				free(szReturnedName);
				szReturnedName = NULL;
			}
		}
	}
	EIDCardLibraryTrace(WINEVENT_LEVEL_INFO,L"GetUserNameFromCertificate = %s",szReturnedName);
	return szReturnedName;
}

PCCERT_CONTEXT GetCertificateFromCspInfo(__in PEID_SMARTCARD_CSP_INFO pCspInfo)
{
	
	if (_tcscmp(pCspInfo->bBuffer + pCspInfo->nCSPNameOffset,TBEIDCSP ) == 0)
	{
		EIDCardLibraryTrace(WINEVENT_LEVEL_INFO,L"GetBEIDCertificateFromCspInfo");
		return GetBEIDCertificateFromCspInfo(pCspInfo);
	}
	EIDCardLibraryTrace(WINEVENT_LEVEL_INFO,L"GetCertificateFromCspInfo");
	HCRYPTPROV hProv = NULL;
	DWORD dwError = 0;
	PCCERT_CONTEXT pCertContext = NULL;
	BYTE Data[4096];
	DWORD DataSize = ARRAYSIZE(Data);
	LPTSTR szContainerName = pCspInfo->bBuffer + pCspInfo->nContainerNameOffset;
	LPTSTR szProviderName = pCspInfo->bBuffer + pCspInfo->nCSPNameOffset;
	HCRYPTKEY phUserKey = NULL;
	__try
	{
		// check input
		if (GetPolicyValue(AllowSignatureOnlyKeys) == 0 && pCspInfo->KeySpec == AT_SIGNATURE)
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Policy denies AT_SIGNATURE Key");
			__leave;
		}

		if (!CryptAcquireContext(&hProv,szContainerName,szProviderName,PROV_RSA_FULL, CRYPT_SILENT))
		{
			dwError = GetLastError();
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"CryptAcquireContext : 0x%08x container='%s' provider='%s'",GetLastError(),szContainerName,szProviderName);
			__leave;
		}
		if (!CryptGetUserKey(hProv, pCspInfo->KeySpec, &phUserKey))
		{
			dwError = GetLastError();
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"CryptGetUserKey : 0x%08x",GetLastError());
			__leave;
		}
		if (!CryptGetKeyParam(phUserKey,KP_CERTIFICATE,(BYTE*)Data,&DataSize,0))
		{
			dwError = GetLastError();
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"CryptGetKeyParam : 0x%08x",GetLastError());
			__leave;
		}
		pCertContext = CertCreateCertificateContext(X509_ASN_ENCODING, Data, DataSize); 
		if (!pCertContext)
		{
			dwError = GetLastError();
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"CertCreateCertificateContext : 0x%08x",GetLastError());
			__leave;
		}
		// save reference to CSP (else we can't access private key)
		CRYPT_KEY_PROV_INFO KeyProvInfo = {0};
		KeyProvInfo.pwszProvName = szProviderName;
		KeyProvInfo.pwszContainerName = szContainerName;
		KeyProvInfo.dwProvType = PROV_RSA_FULL;
		KeyProvInfo.dwKeySpec = pCspInfo->KeySpec;

		if (!CertSetCertificateContextProperty(pCertContext,CERT_KEY_PROV_INFO_PROP_ID,0,&KeyProvInfo))
		{
			dwError = GetLastError();
			CertFreeCertificateContext(pCertContext);
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"CertSetCertificateContextProperty : 0x%08x",dwError);
		}
		EIDCardLibraryTrace(WINEVENT_LEVEL_INFO,L"Certificate OK");

	}
	__finally
	{
		if (phUserKey)
			CryptDestroyKey(phUserKey);
		if (hProv) 
			CryptReleaseContext(hProv,0);
	}
	SetLastError(dwError);
	return pCertContext;
}

#define ERRORTOTEXT(ERROR) case ERROR: pszName = TEXT(#ERROR);                 break;
LPCTSTR GetTrustErrorText(DWORD Status)
{
    LPCTSTR pszName = NULL;
    switch(Status)
    {
		ERRORTOTEXT(CERT_E_EXPIRED)
		ERRORTOTEXT(CERT_E_VALIDITYPERIODNESTING)
		ERRORTOTEXT(CERT_E_ROLE)
		ERRORTOTEXT(CERT_E_PATHLENCONST)
		ERRORTOTEXT(CERT_E_CRITICAL)
		ERRORTOTEXT(CERT_E_PURPOSE)
		ERRORTOTEXT(CERT_E_ISSUERCHAINING)
		ERRORTOTEXT(CERT_E_MALFORMED)
		ERRORTOTEXT(CERT_E_UNTRUSTEDROOT)
		ERRORTOTEXT(CERT_E_CHAINING)
		ERRORTOTEXT(TRUST_E_FAIL)
		ERRORTOTEXT(CERT_E_REVOKED)
		ERRORTOTEXT(CERT_E_UNTRUSTEDTESTROOT)
		ERRORTOTEXT(CERT_E_REVOCATION_FAILURE)
		ERRORTOTEXT(CERT_E_CN_NO_MATCH)
		ERRORTOTEXT(CERT_E_WRONG_USAGE)
		ERRORTOTEXT(CERT_TRUST_NO_ERROR)
		ERRORTOTEXT(CERT_TRUST_IS_NOT_TIME_VALID)
		ERRORTOTEXT(CERT_TRUST_IS_NOT_TIME_NESTED)
		ERRORTOTEXT(CERT_TRUST_IS_REVOKED)
		ERRORTOTEXT(CERT_TRUST_IS_NOT_SIGNATURE_VALID)
		ERRORTOTEXT(CERT_TRUST_IS_NOT_VALID_FOR_USAGE)
		ERRORTOTEXT(CERT_TRUST_IS_UNTRUSTED_ROOT)
		ERRORTOTEXT(CERT_TRUST_REVOCATION_STATUS_UNKNOWN)
		ERRORTOTEXT(CERT_TRUST_IS_CYCLIC)
		ERRORTOTEXT(CERT_TRUST_IS_PARTIAL_CHAIN)
		ERRORTOTEXT(CERT_TRUST_CTL_IS_NOT_TIME_VALID)
		ERRORTOTEXT(CERT_TRUST_CTL_IS_NOT_SIGNATURE_VALID)
		ERRORTOTEXT(CERT_TRUST_CTL_IS_NOT_VALID_FOR_USAGE)
		default:                            
			pszName = NULL;                      break;
    }
	return pszName;
} 
#undef ERRORTOTEXT

BOOL IsTrustedCertificate(__in PCCERT_CONTEXT pCertContext, __in_opt DWORD dwFlag)
{
    //
    // Validate certificate chain.
    //
	BOOL fValidation = FALSE;
	PCERT_ENHKEY_USAGE		 pCertUsage        = NULL;
	PCCERT_CHAIN_CONTEXT     pChainContext     = NULL;
	CERT_ENHKEY_USAGE        EnhkeyUsage       = {0};
	CERT_USAGE_MATCH         CertUsage         = {0};  
	CERT_CHAIN_PARA          ChainPara         = {0};
	CERT_CHAIN_POLICY_PARA   ChainPolicy       = {0};
	CERT_CHAIN_POLICY_STATUS PolicyStatus      = {0};
	LPSTR					szOid;
	HCERTCHAINENGINE		hChainEngine		= HCCE_LOCAL_MACHINE;
	DWORD dwError = 0, dwSize = 0, dwI;

	//---------------------------------------------------------
    // Initialize data structures for chain building.
	EnhkeyUsage.cUsageIdentifier = 0;
	EnhkeyUsage.rgpszUsageIdentifier=NULL;
	CertUsage.dwType = USAGE_MATCH_TYPE_AND;
    CertUsage.Usage  = EnhkeyUsage;

	memset(&ChainPara, 0, sizeof(CERT_CHAIN_PARA));
    ChainPara.cbSize = sizeof(CERT_CHAIN_PARA);
    ChainPara.RequestedUsage=CertUsage;

	memset(&ChainPolicy, 0, sizeof(CERT_CHAIN_POLICY_PARA));
    ChainPolicy.cbSize = sizeof(CERT_CHAIN_POLICY_PARA);

	memset(&PolicyStatus, 0, sizeof(CERT_CHAIN_POLICY_STATUS));
    PolicyStatus.cbSize = sizeof(CERT_CHAIN_POLICY_STATUS);
    PolicyStatus.lChainIndex = -1;
    PolicyStatus.lElementIndex = -1;

	if (dwFlag & EID_CERTIFICATE_FLAG_USERSTORE)
	{
		hChainEngine = HCCE_CURRENT_USER;
	}
	
	__try
	{
		if (!GetPolicyValue(AllowCertificatesWithNoEKU))
		{
			// check EKU SmartCardLogon
			EnhkeyUsage.cUsageIdentifier = 1;
			szOid = szOID_KP_SMARTCARD_LOGON;
			EnhkeyUsage.rgpszUsageIdentifier=& szOid;
			CertUsage.dwType = USAGE_MATCH_TYPE_OR;

			if (!CertGetEnhancedKeyUsage(pCertContext, 0, NULL, &dwSize))
			{
				EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Error 0x%x returned by CertGetEnhancedKeyUsage", GetLastError());
				__leave;
			}
			pCertUsage = (PCERT_ENHKEY_USAGE)malloc(dwSize);
			if (!pCertUsage)
			{
				EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Error 0x%x returned by malloc", GetLastError());
				__leave;
			}
			if (!CertGetEnhancedKeyUsage(pCertContext, 0, pCertUsage, &dwSize))
			{
				EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Error 0x%x returned by CertGetEnhancedKeyUsage", GetLastError());
				__leave;
			}
			for (dwI = 0; dwI < pCertUsage->cUsageIdentifier; dwI++)
			{
				if (strcmp(pCertUsage->rgpszUsageIdentifier[dwI],szOID_KP_SMARTCARD_LOGON) == 0)
				{
					break;
				}
			}
			if (dwI >= pCertUsage->cUsageIdentifier)
			{
				dwError = CERT_TRUST_IS_NOT_VALID_FOR_USAGE;
				EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"No EKU found in end certificate");
				__leave;
			}

		}
	    if(!CertGetCertificateChain(
			hChainEngine,pCertContext,NULL,NULL,&ChainPara,CERT_CHAIN_ENABLE_PEER_TRUST,NULL,&pChainContext))
		{
			dwError = GetLastError();
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Error 0x%x returned by CertGetCertificateChain", GetLastError());
			__leave;
		}

		if (pChainContext->TrustStatus.dwErrorStatus)
		{
			dwError = pChainContext->TrustStatus.dwErrorStatus;
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Error %s (0x%x) returned by CertVerifyCertificateChainPolicy",GetTrustErrorText(pChainContext->TrustStatus.dwErrorStatus),pChainContext->TrustStatus.dwErrorStatus);
			__leave;
		}
		if(! CertVerifyCertificateChainPolicy(CERT_CHAIN_POLICY_BASE, pChainContext, &ChainPolicy, &PolicyStatus))
		{
			dwError = GetLastError();
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Error 0x%x returned by CertGetCertificateChain", GetLastError());
			__leave;
		}
		if(PolicyStatus.dwError)
		{
			dwError = PolicyStatus.dwError;
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Error %s %d returned by CertVerifyCertificateChainPolicy",GetTrustErrorText(PolicyStatus.dwError),PolicyStatus.dwError);
			__leave;
		} 
		EIDCardLibraryTrace(WINEVENT_LEVEL_INFO,L"Chain OK");

		// verifiate time compliance
		if (!GetPolicyValue(AllowTimeInvalidCertificates))
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_INFO,L"Timecheck");
			LPFILETIME pTimeToVerify = NULL;
			if (CertVerifyTimeValidity(pTimeToVerify, pCertContext->pCertInfo))
			{
				EIDCardLibraryTrace(WINEVENT_LEVEL_INFO,L"Timecheck invalid");
				__leave;
			}
		}

		fValidation = TRUE;
		EIDCardLibraryTrace(WINEVENT_LEVEL_INFO,L"Valid");
	}
	__finally
	{
		if (pCertUsage)
			free(pCertUsage);
		if (pChainContext)
			CertFreeCertificateChain(pChainContext);
	}

	SetLastError(dwError);
	return fValidation;
}

BOOL MakeTrustedCertifcate(PCCERT_CONTEXT pCertContext)
{

	BOOL fReturn = FALSE;
	PCCERT_CHAIN_CONTEXT     pChainContext     = NULL;
	CERT_ENHKEY_USAGE        EnhkeyUsage       = {0};
	CERT_USAGE_MATCH         CertUsage         = {0};  
	CERT_CHAIN_PARA          ChainPara         = {0};
	CERT_CHAIN_POLICY_PARA   ChainPolicy       = {0};
	CERT_CHAIN_POLICY_STATUS PolicyStatus      = {0};
	LPSTR					szOid;
	HCERTSTORE hRootStore = NULL;
	HCERTSTORE hTrustStore = NULL;
	HCERTSTORE hTrustedPeople = NULL;
	// because machine cert are trusted by user,
	// build the chain in user context (if used certifcates are trusted only by the user
	// - think about program running in user space)
	HCERTCHAINENGINE		hChainEngine		= HCCE_CURRENT_USER;
	DWORD dwError = 0;

	//---------------------------------------------------------
    // Initialize data structures for chain building.

	if (GetPolicyValue(AllowCertificatesWithNoEKU))
	{
		EnhkeyUsage.cUsageIdentifier = 0;
		EnhkeyUsage.rgpszUsageIdentifier=NULL;
	}
	else
	{
		EnhkeyUsage.cUsageIdentifier = 1;
		szOid = szOID_KP_SMARTCARD_LOGON;
		EnhkeyUsage.rgpszUsageIdentifier=& szOid;
	}

	CertUsage.dwType = USAGE_MATCH_TYPE_AND;
    CertUsage.Usage  = EnhkeyUsage;

	memset(&ChainPara, 0, sizeof(CERT_CHAIN_PARA));
    ChainPara.cbSize = sizeof(CERT_CHAIN_PARA);
    ChainPara.RequestedUsage=CertUsage;

	memset(&ChainPolicy, 0, sizeof(CERT_CHAIN_POLICY_PARA));
    ChainPolicy.cbSize = sizeof(CERT_CHAIN_POLICY_PARA);

	memset(&PolicyStatus, 0, sizeof(CERT_CHAIN_POLICY_STATUS));
    PolicyStatus.cbSize = sizeof(CERT_CHAIN_POLICY_STATUS);
    PolicyStatus.lChainIndex = -1;
    PolicyStatus.lElementIndex = -1;

    //-------------------------------------------------------------------
    // Build a chain using CertGetCertificateChain
    __try
	{
		fReturn = CertGetCertificateChain(hChainEngine,pCertContext,NULL,NULL,&ChainPara,CERT_CHAIN_ENABLE_PEER_TRUST,NULL,&pChainContext);
		if (!fReturn)
		{
			dwError = GetLastError();
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Error 0x%08x returned by CertGetCertificateChain", dwError);
			__leave;
		}
		// pChainContext->cChain -1 is the final chain num
		DWORD dwCertificateCount = pChainContext->rgpChain[pChainContext->cChain -1]->cElement;
		if (dwCertificateCount == 1)
		{
			hTrustedPeople = CertOpenStore(CERT_STORE_PROV_SYSTEM,0,NULL,CERT_SYSTEM_STORE_LOCAL_MACHINE,_T("TrustedPeople"));
			if (!hTrustedPeople)
			{
				dwError = GetLastError();
				EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Error 0x%08x returned by CertOpenStore", dwError);
				fReturn = FALSE;
				__leave;
			}
			fReturn = CertAddCertificateContextToStore(hTrustedPeople,
					pChainContext->rgpChain[pChainContext->cChain -1]->rgpElement[0]->pCertContext,
					CERT_STORE_ADD_USE_EXISTING,NULL);
		}
		else
		{
			hRootStore = CertOpenStore(CERT_STORE_PROV_SYSTEM,0,NULL,CERT_SYSTEM_STORE_LOCAL_MACHINE,_T("Root"));
			if (!hRootStore)
			{
				dwError = GetLastError();
				EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Error 0x%08x returned by CertOpenStore", dwError);
				fReturn = FALSE;
				__leave;
			}
			hTrustStore = CertOpenStore(CERT_STORE_PROV_SYSTEM,0,NULL,CERT_SYSTEM_STORE_LOCAL_MACHINE,_T("CA"));
			if (!hTrustStore)
			{
				dwError = GetLastError();
				EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Error 0x%08x returned by CertOpenStore", dwError);
				fReturn = FALSE;
				__leave;
			}
			for (DWORD i = dwCertificateCount - 1 ; i > 0 ; i--)
			{
				if (i < dwCertificateCount - 1)
				{
					// second & so on don't have to be trusted
					fReturn = CertAddCertificateContextToStore(hTrustStore,
						pChainContext->rgpChain[pChainContext->cChain -1]->rgpElement[i]->pCertContext,
						CERT_STORE_ADD_USE_EXISTING,NULL);
				}
				else
				{
					// first must be trusted
					fReturn = CertAddCertificateContextToStore(hRootStore,
						pChainContext->rgpChain[pChainContext->cChain -1]->rgpElement[i]->pCertContext,
						CERT_STORE_ADD_USE_EXISTING,NULL);
				}
				if (!fReturn)
				{
					dwError = GetLastError();
					EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Error 0x%08x returned by CertAddCertificateContextToStore", dwError);
					__leave;
				}
			}
		}
	}
	__finally
	{
		if (hTrustedPeople)
			CertCloseStore(hTrustedPeople,0);
		if (hRootStore)
			CertCloseStore(hRootStore,0);
		if (hTrustStore)
			CertCloseStore(hTrustStore,0);
		if (pChainContext)
			CertFreeCertificateChain(pChainContext);
	}
	SetLastError(dwError);
	return fReturn;
}