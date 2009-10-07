/*	EID Authentication
    Copyright (C) 2009 Vincent Le Toux

    This library is EIDFree software; you can redistribute it and/or
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

#include <ntstatus.h>
#define WIN32_NO_STATUS
#include <windows.h>
#include <tchar.h>
#include <intsafe.h>
#include <wincred.h>
#include <Lm.h>

#include <Ntsecapi.h>
#define SECURITY_WIN32
#include <sspi.h>
#include <ntsecpkg.h>
#include <Wtsapi32.h>


#include <CodeAnalysis/warnings.h>
#pragma warning(push)
#pragma warning(disable : ALL_CODE_ANALYSIS_WARNINGS)
#include <strsafe.h>
#pragma warning(pop)

#include <credentialprovider.h>
#pragma warning(push)
#pragma warning(disable : 4995)
#include <shlwapi.h>
#pragma warning(pop)

#include "EIDCardLibrary.h"
#include "Tracing.h"
#include "StoredCredentialManagement.h"

#pragma comment(lib, "Secur32.lib")
#pragma comment(lib, "Netapi32.lib")
#pragma comment(lib, "Wtsapi32.lib")

PVOID EIDAlloc(DWORD dwSize)
{
	return malloc(dwSize);
}
VOID EIDFree(PVOID buffer)
{
	free(buffer);
}

//
// This function copies the length of pwz and the pointer pwz into the UNICODE_STRING structure
// This function is intended for serializing a credential in GetSerialization only.
// Note that this function just makes a copy of the string pointer. It DOES NOT ALLOCATE storage!
// Be very, very sure that this is what you want, because it probably isn't outside of the
// exact GetSerialization call where the sample uses it.
//
HRESULT UnicodeStringInitWithString(
                                       PWSTR pwz,
                                       UNICODE_STRING* pus
                                       )
{
    HRESULT hr;
    if (pwz)
    {
        size_t lenString;
        hr = StringCchLengthW(pwz, USHORT_MAX, &(lenString));

        if (SUCCEEDED(hr))
        {
            USHORT usCharCount;
            hr = SizeTToUShort(lenString, &usCharCount);
            if (SUCCEEDED(hr))
            {
                USHORT usSize;
                hr = SizeTToUShort(sizeof(WCHAR), &usSize);
                if (SUCCEEDED(hr))
                {
                    hr = UShortMult(usCharCount, usSize, &(pus->Length)); // Explicitly NOT including NULL terminator
                    if (SUCCEEDED(hr))
                    {
                        pus->MaximumLength = pus->Length;
                        pus->Buffer = pwz;
                        hr = S_OK;
                    }
                    else
                    {
                        hr = HRESULT_FROM_WIN32(ERROR_ARITHMETIC_OVERFLOW);
                    }
                }
            }
        }
    }
    else
    {
        hr = E_INVALIDARG;
    }
    return hr;
}



//
// The following function is intended to be used ONLY with the Kerb*Pack functions.  It does
// no bounds-checking because its callers have precise requirements and are written to respect 
// its limitations.
// You can read more about the UNICODE_STRING type at:
// http://msdn.microsoft.com/library/default.asp?url=/library/en-us/secauthn/security/unicode_string.asp
//
static void _UnicodeStringPackedUnicodeStringCopy(
    const UNICODE_STRING& rus,
    PWSTR pwzBuffer,
    UNICODE_STRING* pus
    )
{
    pus->Length = rus.Length;
    pus->MaximumLength = rus.Length;
    pus->Buffer = pwzBuffer;

    CopyMemory(pus->Buffer, rus.Buffer, pus->Length);
}

//
// WinLogon and LSA consume "packed" KERB_INTERACTIVE_UNLOCK_LOGONs.  In these, the PWSTR members of each
// UNICODE_STRING are not actually pointers but byte offsets into the overall buffer represented
// by the packed KERB_INTERACTIVE_UNLOCK_LOGON.  For example:
// 
// rkiulIn.Logon.LogonDomainName.Length = 14                                    -> Length is in bytes, not characters
// rkiulIn.Logon.LogonDomainName.Buffer = sizeof(KERB_INTERACTIVE_UNLOCK_LOGON) -> LogonDomainName begins immediately
//                                                                              after the KERB_... struct in the buffer
// rkiulIn.Logon.UserName.Length = 10
// rkiulIn.Logon.UserName.Buffer = sizeof(KERB_INTERACTIVE_UNLOCK_LOGON) + 14   -> UNICODE_STRINGS are NOT null-terminated
//
// rkiulIn.Logon.Password.Length = 16
// rkiulIn.Logon.Password.Buffer = sizeof(KERB_INTERACTIVE_UNLOCK_LOGON) + 14 + 10
// 
// THere's more information on this at:
// http://msdn.microsoft.com/msdnmag/issues/05/06/SecurityBriefs/#void
//

HRESULT EIDUnlockLogonPack(
									   const EID_INTERACTIVE_UNLOCK_LOGON& rkiulIn,
									   const PEID_SMARTCARD_CSP_INFO pCspInfo,
                                       BYTE** prgb,
                                       DWORD* pcb
                                       )
{
    HRESULT hr;

    const EID_INTERACTIVE_LOGON* pkilIn = &rkiulIn.Logon;

    // alloc space for struct plus extra for the three strings
    DWORD cb = sizeof(rkiulIn) +
		pkilIn->LogonDomainName.Length +
        pkilIn->UserName.Length +
        pkilIn->Pin.Length +
		pCspInfo->dwCspInfoLen;


    EID_INTERACTIVE_UNLOCK_LOGON* pkiulOut = (EID_INTERACTIVE_UNLOCK_LOGON*)CoTaskMemAlloc(cb);

    if (pkiulOut)
    {
        ZeroMemory(&pkiulOut->LogonId, sizeof(LUID));

        //
        // point pbBuffer at the beginning of the extra space
        //
        BYTE* pbBuffer = (BYTE*)pkiulOut + sizeof(*pkiulOut);

        //
        // set up the Logon structure within the EID_INTERACTIVE_UNLOCK_LOGON
        //
        EID_INTERACTIVE_LOGON* pkilOut = &pkiulOut->Logon;
		//KERB_INTERACTIVE_LOGON* pkilOut = &pkiulOut->Logon;

        pkilOut->MessageType = pkilIn->MessageType;
		pkilOut->Flags = pkilIn->Flags;

        //
        // copy each string,
        // fix up appropriate buffer pointer to be offset,
        // advance buffer pointer over copied characters in extra space
        //
        _UnicodeStringPackedUnicodeStringCopy(pkilIn->LogonDomainName, (PWSTR)pbBuffer, &pkilOut->LogonDomainName);
        pkilOut->LogonDomainName.Buffer = (PWSTR)(pbBuffer - (BYTE*)pkiulOut);
        pbBuffer += pkilOut->LogonDomainName.Length;

        _UnicodeStringPackedUnicodeStringCopy(pkilIn->UserName, (PWSTR)pbBuffer, &pkilOut->UserName);
        pkilOut->UserName.Buffer = (PWSTR)(pbBuffer - (BYTE*)pkiulOut);
        pbBuffer += pkilOut->UserName.Length;

        _UnicodeStringPackedUnicodeStringCopy(pkilIn->Pin, (PWSTR)pbBuffer, &pkilOut->Pin);
        pkilOut->Pin.Buffer = (PWSTR)(pbBuffer - (BYTE*)pkiulOut);
		pbBuffer += pkilOut->Pin.Length;

		pkilOut->CspData = (PUCHAR) (pbBuffer - (BYTE*)pkiulOut);
		pkilOut->CspDataLength = pCspInfo->dwCspInfoLen;

		memcpy(pbBuffer,pCspInfo,pCspInfo->dwCspInfoLen);

        *prgb = (BYTE*)pkiulOut;
        *pcb = cb;

        hr = S_OK;
    }
    else
    {
        hr = E_OUTOFMEMORY;
    }

    return hr;
}


// 
// This function packs the string pszSourceString in pszDestinationString
// for use with LSA functions including LsaLookupAuthenticationPackage.
//
HRESULT LsaInitString(PSTRING pszDestinationString, PCSTR pszSourceString)
{
    size_t cchLength;
    HRESULT hr = StringCchLengthA(pszSourceString, USHORT_MAX, &cchLength);
    if (SUCCEEDED(hr))
    {
        USHORT usLength;
        hr = SizeTToUShort(cchLength, &usLength);

        if (SUCCEEDED(hr))
        {
            pszDestinationString->Buffer = (PCHAR)pszSourceString;
            pszDestinationString->Length = usLength;
            pszDestinationString->MaximumLength = pszDestinationString->Length+1;
            hr = S_OK;
        }
    }
    return hr;
}

//
// Retrieves the 'eid' AuthPackage from the LSA.
//
HRESULT RetrieveNegotiateAuthPackage(ULONG * pulAuthPackage)
{
    HRESULT hr;
    HANDLE hLsa;

    NTSTATUS status = LsaConnectUntrusted(&hLsa);
    if (SUCCEEDED(HRESULT_FROM_NT(status)))
    {

        ULONG ulAuthPackage;
        LSA_STRING lsaszPackageName;
		LsaInitString(&lsaszPackageName, AUTHENTICATIONPACKAGENAME);

        status = LsaLookupAuthenticationPackage(hLsa, &lsaszPackageName, &ulAuthPackage);
        if (SUCCEEDED(HRESULT_FROM_NT(status)))
        {
            *pulAuthPackage = ulAuthPackage;
            hr = S_OK;
        }
        else
        {
            hr = HRESULT_FROM_NT(status);
        }
        LsaDeregisterLogonProcess(hLsa);
    }
    else
    {
        hr= HRESULT_FROM_NT(status);
    }

    return hr;
}

//szAuthPackageValue must be freed by  LsaFreeMemory
HRESULT CallAuthPackage(LPCWSTR username ,LPWSTR * szAuthPackageValue, PULONG szAuthPackageLen)
{
    NET_API_STATUS netStatus;
	HRESULT hr;
    HANDLE hLsa;
	DWORD dwRid,dwSubAuthorityCount;
	USER_INFO_23* pUserInfo;
	PSID pSid;
	
	// transform the username to usernameinfo
	netStatus = NetUserGetInfo(NULL,username,23,(LPBYTE*) &pUserInfo);
	if (NERR_Success != netStatus)
	{
		return MAKE_HRESULT(1,FACILITY_INTERNET,netStatus);
	}
	// get the sid
	pSid = pUserInfo->usri23_user_sid;
	// get the last identifier of the sid : it's the rid
	dwSubAuthorityCount = *GetSidSubAuthorityCount(pSid);
	dwRid = *GetSidSubAuthority(pSid, dwSubAuthorityCount-1);
	//
    NTSTATUS status = LsaConnectUntrusted(&hLsa);
    if (SUCCEEDED(HRESULT_FROM_NT(status)))
    {

        ULONG ulAuthPackage;
        LSA_STRING lsaszPackageName;
		LsaInitString(&lsaszPackageName, AUTHENTICATIONPACKAGENAME);

        status = LsaLookupAuthenticationPackage(hLsa, &lsaszPackageName, &ulAuthPackage);
        if (SUCCEEDED(HRESULT_FROM_NT(status)))
        {
            status = LsaCallAuthenticationPackage(hLsa, ulAuthPackage, &dwRid, sizeof(DWORD),
				(PVOID *)szAuthPackageValue,szAuthPackageLen,NULL);
			hr = HRESULT_FROM_NT(status);
            
        }
        else
        {
            hr = HRESULT_FROM_NT(status);
        }
        LsaDeregisterLogonProcess(hLsa);
    }
    else
    {
        hr= HRESULT_FROM_NT(status);
    }
	NetApiBufferFree(pUserInfo);
    return hr;
}

// change pointer according ClientAuthenticationBase : the struct is a copy
// so pointer are invalid
VOID RemapPointer(PEID_INTERACTIVE_UNLOCK_LOGON pUnlockLogon, PVOID ClientAuthenticationBase)
{
	EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Diff %d %d",(PUCHAR) pUnlockLogon, (PUCHAR) ClientAuthenticationBase);
	if ((pUnlockLogon->Logon.UserName.Buffer) != NULL)
	{
		EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Remap Logon from %d",pUnlockLogon->Logon.UserName.Buffer);
		pUnlockLogon->Logon.UserName.Buffer = PWSTR((DWORD)( pUnlockLogon) + (PUCHAR) pUnlockLogon->Logon.UserName.Buffer);
		EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Remap Logon to %d",pUnlockLogon->Logon.UserName.Buffer);
	}
	if ((pUnlockLogon->Logon.LogonDomainName.Buffer) != NULL)
	{
		EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Remap LogonDomainName from %d",pUnlockLogon->Logon.LogonDomainName.Buffer);
		pUnlockLogon->Logon.LogonDomainName.Buffer = PWSTR((DWORD)( pUnlockLogon) + (PUCHAR) pUnlockLogon->Logon.LogonDomainName.Buffer);
		EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Remap LogonDomainName to %d",pUnlockLogon->Logon.LogonDomainName.Buffer);
	}
	if ((pUnlockLogon->Logon.Pin.Buffer) != NULL)
	{
		EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Remap Pin from %d",pUnlockLogon->Logon.Pin.Buffer);
		pUnlockLogon->Logon.Pin.Buffer = PWSTR((DWORD)( pUnlockLogon) + (PUCHAR) pUnlockLogon->Logon.Pin.Buffer);
		EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Remap Pin to %d",pUnlockLogon->Logon.Pin.Buffer);
	}
	if ((pUnlockLogon->Logon.CspData) != NULL)
	{
		EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Remap CSPData from %d",pUnlockLogon->Logon.CspData);
		pUnlockLogon->Logon.CspData = PUCHAR( (PBYTE)pUnlockLogon + (DWORD) pUnlockLogon->Logon.CspData);
		EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Remap CSPData to %d",pUnlockLogon->Logon.CspData);
	}
	EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Leave");
}

VOID EIDDebugPrintEIDUnlockLogonStruct(UCHAR dwLevel, PEID_INTERACTIVE_UNLOCK_LOGON pUnlockLogon) {
	WCHAR Buffer[1000];
	EIDCardLibraryTrace(dwLevel,L"LogonId %d %d",pUnlockLogon->LogonId.LowPart,pUnlockLogon->LogonId.HighPart);
	EIDCardLibraryTrace(dwLevel,L"Username %d",pUnlockLogon->Logon.UserName.Length);
	if ((pUnlockLogon->Logon.UserName.Buffer) != NULL)
	{
		wcsncpy_s(Buffer,1000,pUnlockLogon->Logon.UserName.Buffer,pUnlockLogon->Logon.UserName.Length/2);
		Buffer[pUnlockLogon->Logon.UserName.Length/2]=0;
		EIDCardLibraryTrace(dwLevel,L"Username '%s'",Buffer);
	}
	else
	{
		EIDCardLibraryTrace(dwLevel,L"No Username");
	}
	EIDCardLibraryTrace(dwLevel,L"LogonDomainName %d",pUnlockLogon->Logon.LogonDomainName.Length);
	if (pUnlockLogon->Logon.LogonDomainName.Buffer != NULL)
	{
		wcsncpy_s(Buffer,1000,pUnlockLogon->Logon.LogonDomainName.Buffer,pUnlockLogon->Logon.LogonDomainName.Length/2);
		Buffer[pUnlockLogon->Logon.LogonDomainName.Length/2]=0;
		EIDCardLibraryTrace(dwLevel,L"LogonDomainName '%s'",Buffer);
	}
	else
	{
		EIDCardLibraryTrace(dwLevel,L"No DomainName");
	}
	EIDCardLibraryTrace(dwLevel,L"Pin %d",pUnlockLogon->Logon.Pin.Length);
	if (pUnlockLogon->Logon.Pin.Buffer != NULL)
	{
		wcsncpy_s(Buffer,1000,pUnlockLogon->Logon.Pin.Buffer,pUnlockLogon->Logon.Pin.Length/2);
		Buffer[pUnlockLogon->Logon.Pin.Length/2]=0;
		//EIDCardLibraryTrace(dwLevel,L"Pin '%s'",Buffer);
	}
	else
	{
		EIDCardLibraryTrace(dwLevel,L"No Pin");
	}
	EIDCardLibraryTrace(dwLevel,L"Flags %d",pUnlockLogon->Logon.Flags);
	EIDCardLibraryTrace(dwLevel,L"MessageType %d",pUnlockLogon->Logon.MessageType);
	EIDCardLibraryTrace(dwLevel,L"CspDataLength %d",pUnlockLogon->Logon.CspDataLength);
	if (pUnlockLogon->Logon.CspData)
	{
		PEID_SMARTCARD_CSP_INFO pCspInfo = (PEID_SMARTCARD_CSP_INFO) pUnlockLogon->Logon.CspData;
		EIDCardLibraryTrace(dwLevel,L"MessageType %d",pCspInfo->MessageType);
		EIDCardLibraryTrace(dwLevel,L"KeySpec %d",pCspInfo->KeySpec);
		if (pCspInfo->nCardNameOffset)
		{
			EIDCardLibraryTrace(dwLevel,L"CardName '%s'",&pCspInfo->bBuffer[pCspInfo->nCardNameOffset]);
		}
		if (pCspInfo->nReaderNameOffset)
		{
			EIDCardLibraryTrace(dwLevel,L"ReaderName '%s'",&pCspInfo->bBuffer[pCspInfo->nReaderNameOffset]);
		}
		if (pCspInfo->nContainerNameOffset)
		{
			EIDCardLibraryTrace(dwLevel,L"ContainerName '%s'",&pCspInfo->bBuffer[pCspInfo->nContainerNameOffset]);
		}
		if (pCspInfo->nCSPNameOffset)
		{
			EIDCardLibraryTrace(dwLevel,L"CSPName '%s'",&pCspInfo->bBuffer[pCspInfo->nCSPNameOffset]);
		}
	}	
}

PTSTR GetUsernameFromRid(__in DWORD dwRid)
{
	NET_API_STATUS Status;
	PUSER_INFO_3 pUserInfo = NULL;
	DWORD dwEntriesRead = 0, dwTotalEntries = 0;
	BOOL fReturn = FALSE;
	DWORD dwError = 0;
	BOOL fFound = FALSE;
	DWORD dwI, dwSize;
	PTSTR szUsername = NULL;
	__try
	{
		Status = NetUserEnum(NULL, 3,0, (PBYTE*) &pUserInfo, MAX_PREFERRED_LENGTH, &dwEntriesRead, &dwTotalEntries, NULL);
		if (Status != NERR_Success)
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"NetUserEnum 0x%08x",Status);
			dwError = Status;
			__leave;
		}
		for (dwI = 0; dwI < dwEntriesRead; dwI++)
		{
			if (dwRid == pUserInfo[dwI].usri3_user_id)
			{
				fFound = TRUE;
				break;
			}
		}
		if (!fFound)
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"not found");
			__leave;
		}
		dwSize = (_tcslen(pUserInfo[dwI].usri3_name) +1);
		szUsername = (PTSTR) EIDAlloc(dwSize *sizeof(TCHAR));
		if (!szUsername)
		{
			dwError = GetLastError();
			EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"EIDAlloc 0x%08x",GetLastError());
			__leave;
		}
		_tcscpy_s(szUsername, dwSize, pUserInfo[dwI].usri3_name);
		fReturn = TRUE;
	}
	__finally
	{
		if (pUserInfo)
			NetApiBufferFree(pUserInfo);
	}
	SetLastError(dwError);
	return szUsername;
}

BOOL IsCurrentUser(PTSTR szUserName)
{
	BOOL fReturn;
	PWSTR szCurrentUserName;
	DWORD dwSize;
	// GetUserName return SYSTEM
	//DWORD dwSessionId = WTSGetActiveConsoleSessionId();
	fReturn = WTSQuerySessionInformation(WTS_CURRENT_SERVER_HANDLE, WTS_CURRENT_SESSION, WTSUserName, &szCurrentUserName, &dwSize);
	if (!fReturn)
	{
		EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"WTSQuerySessionInformationW 0x%08X",GetLastError());
		return FALSE;
	}

	fReturn = wcscmp(szCurrentUserName,szUserName) == 0;
	EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"CurrentUsername = '%s' match with '%s'",szCurrentUserName,szUserName);
	WTSFreeMemory(szCurrentUserName);
	return fReturn;
}

BOOL IsAdmin(PTSTR szUserName)
{
	BOOL fReturn = FALSE;
	WCHAR szAdministratorGroupName[256];
	WCHAR szDomainName[256];
	PLOCALGROUP_USERS_INFO_0 pGroupInfo;
	SID_IDENTIFIER_AUTHORITY NtAuthority = SECURITY_NT_AUTHORITY;
	SID_NAME_USE SidType;
	PSID AdministratorsGroup; 
	DWORD dwEntriesRead, dwTotalEntries, dwSize;
	if (NERR_Success != NetUserGetLocalGroups(NULL, szUserName, 0, LG_INCLUDE_INDIRECT, (PBYTE*)&pGroupInfo,
		MAX_PREFERRED_LENGTH, &dwEntriesRead, &dwTotalEntries))
		return FALSE;
	fReturn = AllocateAndInitializeSid(&NtAuthority,
		2,
		SECURITY_BUILTIN_DOMAIN_RID,
		DOMAIN_ALIAS_RID_ADMINS,
		0, 0, 0, 0, 0, 0,
		&AdministratorsGroup); 
	if(!fReturn) 
	{
		NetApiBufferFree(pGroupInfo);
		return FALSE;
	}
	dwSize = ARRAYSIZE(szAdministratorGroupName);
	if( !LookupAccountSid( NULL, AdministratorsGroup,
								  szAdministratorGroupName, &dwSize, szDomainName, 
								  &dwSize, &SidType ) ) 
	{
		FreeSid(AdministratorsGroup); 
		NetApiBufferFree(pGroupInfo);
		return FALSE;
	}

	for (DWORD dwI = 0; dwI < dwTotalEntries ; dwI++)
	{
		fReturn = wcscmp(szAdministratorGroupName, pGroupInfo[dwI].lgrui0_name) == 0;
		if (fReturn) break;
	}
	
	FreeSid(AdministratorsGroup); 
	NetApiBufferFree(pGroupInfo);
	EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"CurrentUsername = '%s'",szUserName);
	return fReturn;
}

// extract RID from current process
DWORD GetCurrentRid()
{
	DWORD dwSize = 0, dwRid = 0;
	PSID pSid;
	PTOKEN_USER pInfo = NULL;
	HANDLE hToken;
	if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken))
	{
	
		GetTokenInformation(hToken, TokenUser, NULL, 0, &dwSize);
		pInfo = (PTOKEN_USER) EIDAlloc(dwSize);
		if (pInfo)
		{
			if (GetTokenInformation(hToken, TokenUser, pInfo, dwSize, &dwSize))
			{
				pSid = pInfo->User.Sid;
				dwRid = *GetSidSubAuthority(pSid, *GetSidSubAuthorityCount(pSid) -1);
			}
			else
			{
				EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Error 0x%08x returned by GetTokenInformation", GetLastError());
			}
			EIDFree(pInfo);
		}
		else
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Error 0x%08x returned by EIDAlloc", GetLastError());
		}
	}
	else
	{
		EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Error 0x%08x returned by OpenProcessToken", GetLastError());
	}
	return dwRid;
}

DWORD GetRidFromUsername(LPTSTR szUsername)
{
	BOOL bResult;
	SID_NAME_USE Use;
	PSID pSid = NULL;
	TCHAR checkDomainName[UNCLEN+1];
	DWORD cchReferencedDomainName=0, dwRid = 0;

	DWORD dLengthSid = 0;
	bResult = LookupAccountName(NULL,  szUsername, NULL,&dLengthSid,NULL, &cchReferencedDomainName, &Use);
	
	pSid = EIDAlloc(dLengthSid);
	cchReferencedDomainName=UNCLEN;
	bResult = LookupAccountName(NULL,  szUsername, pSid,&dLengthSid,checkDomainName, &cchReferencedDomainName, &Use);
	if (!bResult) 
	{
		EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Error 0x%08x returned by LookupAccountName", GetLastError());
		return 0;
	}
	dwRid = *GetSidSubAuthority(pSid, *GetSidSubAuthorityCount(pSid) -1);
	EIDFree(pSid);
	return dwRid;
}


BOOL LsaEIDCreateStoredCredential(__in_opt PWSTR szUsername, __in PWSTR szPassword, __in PCCERT_CONTEXT pContext, __in BOOL fEncryptPassword)
{
	BOOL fReturn = FALSE;
	PEID_CALLPACKAGE_BUFFER pBuffer;
    HANDLE hLsa;
	DWORD dwSize;
	NTSTATUS status;
	PBYTE pPointer;
	DWORD dwPasswordSize;
	DWORD dwError;
	if (!szPassword) 
	{
		EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"szPassword null");
		return FALSE;
	}
	
	dwPasswordSize = (DWORD) (wcslen(szPassword) + 1) * sizeof(WCHAR);
	dwSize = (DWORD) (sizeof(EID_CALLPACKAGE_BUFFER) + dwPasswordSize + pContext->cbCertEncoded); //+ dwProviderSize + dwContainerSize;

	pBuffer = (PEID_CALLPACKAGE_BUFFER) EIDAlloc(dwSize);
	if( !pBuffer) 
	{
		EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"pBuffer null");
		return FALSE;
	}
	if (!szUsername) 
	{
		pBuffer->dwRid = GetCurrentRid();
	}
	else
	{
		pBuffer->dwRid = GetRidFromUsername(szUsername);
	}
	pBuffer->MessageType = EIDCMCreateStoredCredential;
	pBuffer->usPasswordLen = 0;
	pPointer = (PBYTE) &(pBuffer[1]);

	pBuffer->szPassword = (PWSTR) pPointer;
	memcpy(pPointer, szPassword, dwPasswordSize);
	pPointer += dwPasswordSize;
	
	pBuffer->dwCertificateSize = (USHORT) pContext->cbCertEncoded;
	pBuffer->fEncryptPassword = fEncryptPassword;

	pBuffer->pbCertificate = (PBYTE) pPointer;
	memcpy(pPointer, pContext->pbCertEncoded, pContext->cbCertEncoded);
	pPointer += pContext->cbCertEncoded;
	
	if (!pBuffer->dwRid)
	{
		EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"dwRid = 0");
		EIDFree(pBuffer);
		return FALSE;
	}

    status = LsaConnectUntrusted(&hLsa);
    if (SUCCEEDED(HRESULT_FROM_NT(status)))
    {

        ULONG ulAuthPackage;
        LSA_STRING lsaszPackageName;
        LsaInitString(&lsaszPackageName, AUTHENTICATIONPACKAGENAME);

        status = LsaLookupAuthenticationPackage(hLsa, &lsaszPackageName, &ulAuthPackage);
        
		if (status == STATUS_SUCCESS)
        {
            status = LsaCallAuthenticationPackage(hLsa, ulAuthPackage, pBuffer, dwSize, NULL, NULL, NULL);
			if (status == STATUS_SUCCESS)
			{
				fReturn = TRUE;
			}
			else
			{
				EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"LsaCallAuthenticationPackage 0x%08x",status);
			}
        }
		else
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"LsaLookupAuthenticationPackage 0x%08x",status);
		}
    }
	else
	{
		EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"LsaConnectUntrusted 0x%08x",status);
	}
	LsaClose(hLsa);
	dwError = pBuffer->dwError;
	EIDFree(pBuffer);
	SetLastError(dwError);
	return fReturn;
}

DWORD LsaEIDGetRIDFromStoredCredential(__in PCCERT_CONTEXT pContext)
{
	BOOL fReturn = FALSE;
	PEID_CALLPACKAGE_BUFFER pBuffer;
    HANDLE hLsa;
	DWORD dwSize;
	NTSTATUS status;
	PBYTE pPointer;
	DWORD dwError;

	dwSize = (DWORD) (sizeof(EID_CALLPACKAGE_BUFFER) + pContext->cbCertEncoded); 

	pBuffer = (PEID_CALLPACKAGE_BUFFER) EIDAlloc(dwSize);
	if( !pBuffer) 
	{
		EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"pBuffer null");
		return FALSE;
	}

	pBuffer->dwRid = 0;

	pBuffer->MessageType = EIDCMGetStoredCredentialRid;
	pBuffer->usPasswordLen = 0;
	pBuffer->szPassword = NULL;	
	pBuffer->dwCertificateSize = (USHORT) pContext->cbCertEncoded;
	pPointer = (PBYTE) &(pBuffer[1]);
	pBuffer->pbCertificate = (PBYTE) pPointer;
	memcpy(pPointer, pContext->pbCertEncoded, pContext->cbCertEncoded);
	pPointer += pContext->cbCertEncoded;
	
    status = LsaConnectUntrusted(&hLsa);
    if (SUCCEEDED(HRESULT_FROM_NT(status)))
    {

        ULONG ulAuthPackage;
        LSA_STRING lsaszPackageName;
        LsaInitString(&lsaszPackageName, AUTHENTICATIONPACKAGENAME);

        status = LsaLookupAuthenticationPackage(hLsa, &lsaszPackageName, &ulAuthPackage);
        
		if (status == STATUS_SUCCESS)
        {
            status = LsaCallAuthenticationPackage(hLsa, ulAuthPackage, pBuffer, dwSize, NULL, NULL, NULL);
			if (status == STATUS_SUCCESS)
			{
				fReturn = TRUE;
			}
			else
			{
				EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"LsaCallAuthenticationPackage 0x%08x",status);
			}
        }
		else
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"LsaLookupAuthenticationPackage 0x%08x",status);
		}
    }
	else
	{
		EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"LsaConnectUntrusted 0x%08x",status);
	}
	LsaClose(hLsa);
	dwError = pBuffer->dwError;
	EIDFree(pBuffer);
	SetLastError(dwError);
	return pBuffer->dwRid;
}

BOOL IsEIDPackageAvailable()
{
    BOOL fReturn = FALSE;
	HANDLE hLsa;
	NTSTATUS status = LsaConnectUntrusted(&hLsa);
    if (status == STATUS_SUCCESS)
    {
        ULONG ulAuthPackage;
        LSA_STRING lsaszPackageName;
        LsaInitString(&lsaszPackageName, AUTHENTICATIONPACKAGENAME);

        status = LsaLookupAuthenticationPackage(hLsa, &lsaszPackageName, &ulAuthPackage);
		if (status == STATUS_SUCCESS)
		{
			fReturn = TRUE;
		}
		LsaClose(hLsa);
	}
	return fReturn;
}

BOOL LsaEIDRemoveStoredCredential(__in_opt PWSTR szUsername)
{
	BOOL fReturn = FALSE;
	PEID_CALLPACKAGE_BUFFER pBuffer;
    HANDLE hLsa;
	DWORD dwSize;
	NTSTATUS status;
	DWORD dwError = 0;

	dwSize = sizeof(EID_CALLPACKAGE_BUFFER);
	pBuffer = (PEID_CALLPACKAGE_BUFFER) EIDAlloc(dwSize);
	if( !pBuffer) 
	{
		dwError = GetLastError();
		EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"pBuffer null 0x%08X",dwError);
		SetLastError(dwError);
		return FALSE;
	}
	if (!szUsername) 
	{
		pBuffer->dwRid = GetCurrentRid();
	}
	else
	{
		pBuffer->dwRid = GetRidFromUsername(szUsername);
	}
	pBuffer->MessageType = EIDCMRemoveStoredCredential;
	if (!pBuffer->dwRid)
	{
		dwError = GetLastError();
		EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"dwRid = 0");
		EIDFree(pBuffer);
		SetLastError(dwError);
		return FALSE;
	}

    status = LsaConnectUntrusted(&hLsa);
    if (status == STATUS_SUCCESS)
    {

        ULONG ulAuthPackage;
        LSA_STRING lsaszPackageName;
        LsaInitString(&lsaszPackageName, AUTHENTICATIONPACKAGENAME);

        status = LsaLookupAuthenticationPackage(hLsa, &lsaszPackageName, &ulAuthPackage);
        
		if (status == STATUS_SUCCESS)
        {
            status = LsaCallAuthenticationPackage(hLsa, ulAuthPackage, pBuffer, dwSize, NULL, NULL, NULL);
			if (status == STATUS_SUCCESS)
			{
				fReturn = TRUE;
			}
			else
			{
				EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"LsaCallAuthenticationPackage 0x%08x",status);
				dwError = pBuffer->dwError;
			}
        }
		else
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"LsaLookupAuthenticationPackage 0x%08x",status);
			dwError = status;
		}
    }
	else
	{
		EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"LsaConnectUntrusted 0x%08x",status);
		dwError = status;
	}
	LsaClose(hLsa);
	EIDFree(pBuffer);
	SetLastError(dwError);
	return fReturn;
}

BOOL LsaEIDRemoveAllStoredCredential()
{
	BOOL fReturn = FALSE;
	PEID_CALLPACKAGE_BUFFER pBuffer;
    HANDLE hLsa;
	DWORD dwSize;
	NTSTATUS status;
	DWORD dwError = 0;

	dwSize = sizeof(EID_CALLPACKAGE_BUFFER);
	pBuffer = (PEID_CALLPACKAGE_BUFFER) EIDAlloc(dwSize);
	if( !pBuffer) 
	{
		dwError = GetLastError();
		EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"pBuffer null 0x%08X",dwError);
		SetLastError(dwError);
		return FALSE;
	}
	pBuffer->dwRid = GetCurrentRid();
	
	pBuffer->MessageType = EIDCMRemoveAllStoredCredential;
	if (!pBuffer->dwRid)
	{
		dwError = GetLastError();
		EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"dwRid = 0");
		EIDFree(pBuffer);
		SetLastError(dwError);
		return FALSE;
	}

    status = LsaConnectUntrusted(&hLsa);
    if (status == STATUS_SUCCESS)
    {

        ULONG ulAuthPackage;
        LSA_STRING lsaszPackageName;
        LsaInitString(&lsaszPackageName, AUTHENTICATIONPACKAGENAME);

        status = LsaLookupAuthenticationPackage(hLsa, &lsaszPackageName, &ulAuthPackage);
        
		if (status == STATUS_SUCCESS)
        {
            status = LsaCallAuthenticationPackage(hLsa, ulAuthPackage, pBuffer, dwSize, NULL, NULL, NULL);
			if (status == STATUS_SUCCESS)
			{
				fReturn = TRUE;
			}
			else
			{
				EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"LsaCallAuthenticationPackage 0x%08x",status);
				dwError = pBuffer->dwError;
			}
        }
		else
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"LsaLookupAuthenticationPackage 0x%08x",status);
			dwError = status;
		}
    }
	else
	{
		EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"LsaConnectUntrusted 0x%08x",status);
		dwError = status;
	}
	LsaClose(hLsa);
	EIDFree(pBuffer);
	SetLastError(dwError);
	return fReturn;
}

BOOL LsaEIDHasStoredCredential(__in_opt PWSTR szUsername)
{
	BOOL fReturn = FALSE;
	PEID_CALLPACKAGE_BUFFER pBuffer;
    HANDLE hLsa;
	DWORD dwSize;
	NTSTATUS status;

	dwSize = sizeof(EID_CALLPACKAGE_BUFFER);
	pBuffer = (PEID_CALLPACKAGE_BUFFER) EIDAlloc(dwSize);
	if( !pBuffer) 
	{
		EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"pBuffer null");
		return FALSE;
	}
	if (!szUsername) 
	{
		pBuffer->dwRid = GetCurrentRid();
	}
	else
	{
		pBuffer->dwRid = GetRidFromUsername(szUsername);
	}
	pBuffer->MessageType = EIDCMHasStoredCredential;
	if (!pBuffer->dwRid)
	{
		EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"dwRid = 0");
		EIDFree(pBuffer);
		return FALSE;
	}

    status = LsaConnectUntrusted(&hLsa);
    if (SUCCEEDED(HRESULT_FROM_NT(status)))
    {

        ULONG ulAuthPackage;
        LSA_STRING lsaszPackageName;
        LsaInitString(&lsaszPackageName, AUTHENTICATIONPACKAGENAME);

        status = LsaLookupAuthenticationPackage(hLsa, &lsaszPackageName, &ulAuthPackage);
        
		if (status == STATUS_SUCCESS)
        {
            status = LsaCallAuthenticationPackage(hLsa, ulAuthPackage, pBuffer, dwSize, NULL, NULL, NULL);
			if (status == STATUS_SUCCESS)
			{
				fReturn = TRUE;
			}
			else
			{
				EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"LsaCallAuthenticationPackage 0x%08x",status);
			}
        }
		else
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"LsaLookupAuthenticationPackage 0x%08x",status);
		}
    }
	else
	{
		EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"LsaConnectUntrusted 0x%08x",status);
	}
	LsaClose(hLsa);
	EIDFree(pBuffer);
	return fReturn;
}

BOOL LsaEIDCreateStoredCredential(__in PWSTR szUsername, __in PWSTR szPassword, __in PCCERT_CONTEXT pCertContext)
{
	BOOL fStatus, fFreeProv;
	BOOL fEncryptPassword;
	PBYTE pbPublicKey = NULL;
	DWORD dwKeySpec;
//	DWORD dwPublicKeySize;
	HCRYPTPROV hProv = NULL;
	HCRYPTKEY hKey = NULL;
	DWORD dwError = 0;
	BOOL fReturn = FALSE;
	PBYTE pbHash = NULL;
//	DWORD dwHashSize = 0;
	__try
	{
		fStatus = CryptAcquireCertificatePrivateKey(pCertContext, 0, NULL, &hProv, &dwKeySpec, &fFreeProv);
		if (!fStatus)
		{
			dwError = GetLastError();
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"CryptAcquireCertificatePrivateKey 0x%08x",GetLastError());
			__leave;
		}
		/*fStatus = CryptGetUserKey(hProv, dwKeySpec, &hKey);
		if (!fStatus)
		{
			dwError = GetLastError();
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"CryptGetUserKey 0x%08x",GetLastError());
			__leave;
		}
		fStatus = CryptExportKey( hKey, NULL, PUBLICKEYBLOB, 0, NULL, &dwPublicKeySize);
		if (!fStatus)
		{
			dwError = GetLastError();
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"CryptExportKey 0x%08x",GetLastError());
			__leave;
		}
		pbPublicKey = (PBYTE) EIDAlloc(dwPublicKeySize);
		if (!pbPublicKey)
		{
			dwError = GetLastError();
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"EIDAlloc 0x%08x",GetLastError());
			__leave;
		}
		fStatus = CryptExportKey( hKey, NULL, PUBLICKEYBLOB, 0, pbPublicKey, &dwPublicKeySize);
		if (!fStatus)
		{
			dwError = GetLastError();
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"CryptExportKey 0x%08x",GetLastError());
			__leave;
		}
		fStatus = CryptHashCertificate(NULL, CALG_SHA1, 0, pCertContext->pbCertEncoded, pCertContext->cbCertEncoded, NULL, &dwHashSize);
		if (!fStatus)
		{
			dwError = GetLastError();
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"CryptHashCertificate 0x%08x",GetLastError());
			__leave;
		}
		pbHash = (PBYTE) EIDAlloc(dwHashSize);
		if (!pbHash)
		{
			dwError = GetLastError();
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"EIDAlloc 0x%08x",GetLastError());
			__leave;
		}
		fStatus = CryptHashCertificate(NULL, CALG_SHA1, 0, pCertContext->pbCertEncoded, pCertContext->cbCertEncoded, pbHash, &dwHashSize);
		if (!fStatus)
		{
			dwError = GetLastError();
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"CryptHashCertificate 0x%08x",GetLastError());
			__leave;
		}*/
		fEncryptPassword = CanEncryptPassword(hProv, dwKeySpec, NULL);
		fReturn = LsaEIDCreateStoredCredential(szUsername, szPassword, pCertContext, fEncryptPassword);
		if (!fReturn)
		{
			dwError = GetLastError();
			__leave;
		}
	}
	__finally
	{
		if (pbHash)
			EIDFree(pbHash);
		if (hKey)
			CryptDestroyKey(hKey);
		if (pbPublicKey)
			EIDFree(pbPublicKey);
		if (hProv)
			CryptReleaseContext(hProv, 0);
	}
	SetLastError(dwError);
	return fReturn;
}

BOOL MatchUserOrIsAdmin(__in DWORD dwRid, __in PVOID pClientInfo)
{
	BOOL fReturn = FALSE;
	LUID LogonId = ((SECPKG_CLIENT_INFO*)pClientInfo)->LogonId;
	HANDLE hToken = ((SECPKG_CLIENT_INFO*)pClientInfo)->ClientToken;
	NTSTATUS status;
	PSECURITY_LOGON_SESSION_DATA pLogonSessionData = NULL;
	status = LsaGetLogonSessionData(&LogonId, &pLogonSessionData);
	if (status != STATUS_SUCCESS)
	{
		EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"LsaGetLogonSessionData 0x%08x",status);
	}
	else
	{
		if (dwRid == *GetSidSubAuthority(pLogonSessionData->Sid, *GetSidSubAuthorityCount(pLogonSessionData->Sid) -1))
		{
			fReturn = TRUE;
		}
		else
		{
			/*// match admin group
			////////////////////
			DWORD dwEntries, dwTotalEntries;
			PLOCALGROUP_USERS_INFO_0 GroupInfo;
			PWSTR szUserName = (PWSTR) EIDAlloc(pLogonSessionData->UserName.Length + sizeof(WCHAR));
			memcpy(szUserName, pLogonSessionData->UserName.Buffer, pLogonSessionData->UserName.Length);
			szUserName[pLogonSessionData->UserName.Length/sizeof(WCHAR)] = '\0';
			// get admin sid group
			DWORD cbSid = 0;
			PSID pAdminGroupSid = NULL;
			CreateWellKnownSid(WinBuiltinAdministratorsSid, NULL, NULL, &cbSid);
			pAdminGroupSid = EIDAlloc(cbSid);
			CreateWellKnownSid(WinBuiltinAdministratorsSid, NULL, pAdminGroupSid, &cbSid);
			// get user name - done via lsagetlogonsessiondata
			// get local groups
			if (NERR_Success == NetUserGetLocalGroups(NULL, szUserName, 0, 0, (PBYTE*) &GroupInfo,
															MAX_PREFERRED_LENGTH, &dwEntries, &dwTotalEntries))
			{
				for (DWORD dwI = 0; dwI < dwEntries; dwI++)
				{
					// get sid
					SID_NAME_USE Use;
					PSID pGroupSid;
					WCHAR checkDomainName[UNCLEN+1];
					DWORD cchReferencedDomainName=0;

					DWORD dLengthSid = 0;
					BOOL bResult = LookupAccountNameW(NULL,  szUserName, NULL,&dLengthSid,NULL, &cchReferencedDomainName, &Use);
					
					pGroupSid = EIDAlloc(dLengthSid);
					cchReferencedDomainName=UNCLEN;
					bResult = LookupAccountNameW(NULL,  szUserName, pGroupSid,&dLengthSid,checkDomainName, &cchReferencedDomainName, &Use);
					if (!bResult) 
					{
						// match admin
						if (EqualSid(pAdminGroupSid, pGroupSid))
						{
							fReturn = TRUE;
							break;
						}
					}
				}
				NetApiBufferFree(GroupInfo);
			}
			EIDFree(szUserName);
			*/
			SID_IDENTIFIER_AUTHORITY NtAuthority = SECURITY_NT_AUTHORITY;
			PSID AdministratorsGroup; 
			fReturn = AllocateAndInitializeSid(&NtAuthority,
				2,
				SECURITY_BUILTIN_DOMAIN_RID,
				DOMAIN_ALIAS_RID_ADMINS,
				0, 0, 0, 0, 0, 0,
				&AdministratorsGroup); 
			if(fReturn) 
			{
				if (!CheckTokenMembership( hToken, AdministratorsGroup, &fReturn)) 
				{
					 fReturn = FALSE;
				} 
				FreeSid(AdministratorsGroup); 
			}

		}
		LsaFreeReturnBuffer(pLogonSessionData);
	}
	return fReturn;
}

/*
	NTSTATUS NTAPI LsaApCallPackageUntrusted(
		__in PLSA_SECPKG_FUNCTION_TABLE MyLsaDispatchTable,
	  __in   PLSA_CLIENT_REQUEST ClientRequest,
	  __in   PVOID ProtocolSubmitBuffer,
	  __out  PVOID *ProtocolReturnBuffer,
	  __out  PULONG ReturnBufferLength
	) 
	{
		HKEY phkResult;
		DWORD Status;
		DWORD dwRid = 0;
		TCHAR szBuffer[256];
		DWORD RegType;
		DWORD dwRegSize = 0;
		LPBYTE pbBuffer;
		DWORD i;
		WCHAR * szPointer;
		// \User Account Pictures\ 
		WCHAR pbPattern[] = L"\\User Account Pictures\\";
		DWORD dwPatternSize = sizeof(pbPattern) - sizeof(WCHAR); // to remove the null at the end
		if (!ProtocolSubmitBuffer) 
		{
			return STATUS_INVALID_PARAMETER_2;
		}
		if (!ProtocolReturnBuffer) 
		{
			return STATUS_INVALID_PARAMETER_5;
		}
		if (!ReturnBufferLength) 
		{
			return STATUS_INVALID_PARAMETER_6;
		}
		// get user RID
		dwRid = *((PDWORD) ProtocolSubmitBuffer);

		// get UserTitleKey
		// find the path
		_stprintf_s(szBuffer,256,_T("SAM\\SAM\\Domains\\Account\\Users\\%08X"),dwRid);
		EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"RegOpenKeyEx = %s",szBuffer);
		Status=RegOpenKeyEx(HKEY_LOCAL_MACHINE,szBuffer,0,KEY_READ|KEY_QUERY_VALUE,&phkResult);
		if (Status != ERROR_SUCCESS)
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"RegOpenKeyEx %d",Status);
			return STATUS_INVALID_ACCOUNT_NAME;
		}
		Status = RegQueryValueEx( phkResult,TEXT("UserTile"),NULL,&RegType,NULL,&dwRegSize);
		if (Status != ERROR_SUCCESS)
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"RegQueryValueEx %d",Status);
			RegCloseKey(phkResult);
			return STATUS_CANCELLED;
		}
		pbBuffer = (LPBYTE) EIDAlloc(dwRegSize);
		if (!pbBuffer)
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"pbBuffer null %d",GetLastError());
			RegCloseKey(phkResult);
			return STATUS_CANCELLED;
		}
		Status = RegQueryValueEx( phkResult,TEXT("UserTile"),NULL,&RegType,(LPBYTE)pbBuffer,&dwRegSize);
		if (Status != ERROR_SUCCESS) 
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"RegQueryValueEx %d",Status);
			RegCloseKey(phkResult);
			return STATUS_CANCELLED;
		}
		RegCloseKey(phkResult);
		EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Reg OK");
		// analyze output
		for (i=0; i<dwRegSize - dwPatternSize; i++)
		{
			if (! memcmp(&pbBuffer[i],pbPattern,dwPatternSize))
			{
				// pattern found
				EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Pattern found at %d (max=%d)",i,dwRegSize);
				// find the beginning using ':' (c:\program ...)
				for (  ; i>2; i -=2)
				{
					if (pbBuffer[i] == ':')
					{
						// found
						i -=2;
						EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Pattern begin at %d (max=%d)",i,dwRegSize);
						szPointer = (WCHAR*) &pbBuffer[i];
						*ReturnBufferLength = (wcslen(szPointer)+1) * sizeof(WCHAR);
						// allocate memory
						MyLsaDispatchTable->AllocateClientBuffer(ClientRequest,*ReturnBufferLength,ProtocolReturnBuffer);
						if (!*ProtocolReturnBuffer)
						{
							EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"ProtocolReturnBuffer");
							return STATUS_CANCELLED;
						}
						// copy to buffer
						if (MyLsaDispatchTable->CopyToClientBuffer(ClientRequest,*ReturnBufferLength,*ProtocolReturnBuffer,szPointer)
							!= STATUS_SUCCESS)
						{
							EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"CopyToClientBuffer");
							MyLsaDispatchTable->FreeClientBuffer(ClientRequest, *ProtocolReturnBuffer);
							EIDFree(pbBuffer);
							return STATUS_CANCELLED;
						}
						else
						{
							EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"UserTilePath = %s",szPointer);
							EIDFree(pbBuffer);
							return STATUS_SUCCESS;
						}
					}
				}
				
				break;
			}
		}
		EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Pattern not found");
		EIDFree(pbBuffer);
		return STATUS_CANCELLED;
	}
*/
