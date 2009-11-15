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
#include <Cryptuiapi.h>

#include "EIDCardLibrary.h"
#include "Tracing.h"
#include "CContainer.h"
#include "CertificateValidation.h"
#include "GPO.h"
#include "package.h"
#include "beid.h"

#pragma comment(lib, "Cryptui.lib")

#define REMOVALPOLICYKEY TEXT("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Removal Policy")

CContainer::CContainer(LPCTSTR szReaderName, LPCTSTR szCardName, LPCTSTR szProviderName, LPCTSTR szContainerName, DWORD KeySpec,__in USHORT ActivityCount,PCCERT_CONTEXT pCertContext)
{
	_dwRid = 0;
	_szReaderName = (LPTSTR) EIDAlloc ((DWORD)(sizeof(TCHAR)*(_tcslen(szReaderName)+1)));
	if (_szReaderName)
	{
		_tcscpy_s(_szReaderName,_tcslen(szReaderName)+1,szReaderName);
	}
	_szProviderName = (LPTSTR) EIDAlloc ((DWORD)(sizeof(TCHAR)*(_tcslen(szProviderName)+1)));
	if (_szProviderName)
	{
		_tcscpy_s(_szProviderName,_tcslen(szProviderName)+1,szProviderName);
	}
	_szContainerName = (LPTSTR) EIDAlloc ((DWORD)(sizeof(TCHAR)*(_tcslen(szContainerName)+1)));
	if (_szContainerName)
	{
		_tcscpy_s(_szContainerName,_tcslen(szContainerName)+1,szContainerName);
	}
	_szCardName = (LPTSTR) EIDAlloc ((DWORD)(sizeof(TCHAR)*(_tcslen(szCardName)+1)));
	if (_szCardName)
	{
		_tcscpy_s(_szCardName,_tcslen(szCardName)+1,szCardName);
	}
	_szUserName = NULL;
	_KeySpec = KeySpec;
	_ActivityCount = ActivityCount;
	_pCertContext = pCertContext;
}

CContainer::~CContainer()
{
	if (_szReaderName)
		EIDFree(_szReaderName);
	if (_szCardName)
		EIDFree(_szCardName);
	if (_szProviderName)
		EIDFree(_szProviderName);
	if (_szContainerName)
		EIDFree(_szContainerName);
	if (_szUserName) 
		EIDFree(_szUserName);
	if (_pCertContext) {
		CertFreeCertificateContext(_pCertContext);
	}
}

PTSTR CContainer::GetUserName()
{
	if (_szUserName)
	{
		return _szUserName;
	}
	DWORD dwSize;
	BOOL fReturn = FALSE;
	PCRYPT_KEY_PROV_INFO pKeyProvInfo = NULL;
	__try
	{
		// get the subject details for the cert
		dwSize = CertGetNameString(_pCertContext,CERT_NAME_SIMPLE_DISPLAY_TYPE,0,NULL,NULL,0);
		if (!dwSize)
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"CertGetNameString error = %d",GetLastError());
			__leave;
		}
		_szUserName = (LPTSTR) EIDAlloc(dwSize*sizeof(TCHAR));
		if (!_szUserName) 
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"EIDAlloc error = %d",GetLastError());
			__leave;
		}
		dwSize = CertGetNameString(_pCertContext,CERT_NAME_SIMPLE_DISPLAY_TYPE,0,NULL,_szUserName,dwSize);
		if (!dwSize)
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"CertGetNameString error = %d",GetLastError());
			__leave;
		}
		// remove any weird characters
		// (else we can not match an existing username because it is not accepted as valid username by windows)
		for (DWORD i = 0; i<dwSize; i++)
		{
			TCHAR cChar = _szUserName[i];
			if (cChar < 13 && cChar >0)
			{
				_szUserName[i] = '_';
			}
			if (cChar == '\\' || cChar == ':' || cChar == '+' ||
				cChar == '/' || cChar == ';' || cChar == '=' ||
				cChar == '[' || cChar == '|' || cChar == ',' ||
				cChar == ']' || cChar == '<' || cChar == '?' ||
				cChar == '"' || cChar == '>' || cChar == '*')
			{
				_szUserName[i] = '_';
			}

		}
			// check if it is a Belgian Eid card to drop the '(Authentication)'
		dwSize = 0;
		
		if (!CertGetCertificateContextProperty(_pCertContext, CERT_KEY_PROV_INFO_PROP_ID, NULL, &dwSize))
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Error 0x%08x returned by CertGetCertificateContextProperty", GetLastError());
			__leave;
		}
		pKeyProvInfo = (PCRYPT_KEY_PROV_INFO) EIDAlloc(dwSize);
		if (!pKeyProvInfo)
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Error 0x%08x returned by EIDAlloc", GetLastError());
			__leave;
		}
		if (!CertGetCertificateContextProperty(_pCertContext, CERT_KEY_PROV_INFO_PROP_ID, (PBYTE) pKeyProvInfo, &dwSize))
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Error 0x%08x returned by CertGetCertificateContextProperty", GetLastError());
			__leave;
		}
		if (_tcscmp(pKeyProvInfo->pwszProvName, TBEIDCSP) == 0)
		{
			_szUserName[_tcslen(_szUserName) - 17] = '\0';
		}
		// truncate it to max 20 char
		if (_tcsclen(_szUserName) >= 21) 
			_szUserName[20]=0;
		// remove terminating dot
		for(int i = (int)_tcsclen(_szUserName)-1; i>= 0; i--)
		{
			if (_szUserName[i] == '.')
			{
				_szUserName[i] = '\0';
			}
			else
			{
				break;
			}
			if (i == 0)
			{
				_szUserName[0] = 'a';
			}
		}
		fReturn = TRUE;

	}
	__finally
	{
		if (pKeyProvInfo)
			EIDFree(pKeyProvInfo);
		if (!fReturn)
		{
			if (_szUserName)
			{
				EIDFree(_szUserName);
				_szUserName = NULL;
			}
		}
	}
	EIDCardLibraryTrace(WINEVENT_LEVEL_INFO,L"GetUserNameFromCertificate = %s",_szUserName);
	return _szUserName;
}

DWORD CContainer::GetRid()
{
	if (_dwRid == 0)
	{
		_dwRid = LsaEIDGetRIDFromStoredCredential(_pCertContext);
		EIDCardLibraryTrace(WINEVENT_LEVEL_INFO,L"_dwRid set to %x",_dwRid);
	}
	return _dwRid;
}

PTSTR CContainer::GetProviderName()
{
	return _szProviderName;
}
PTSTR CContainer::GetContainerName()
{
	return _szContainerName;
}
DWORD CContainer::GetKeySpec()
{
	return _KeySpec;
}

PCCERT_CONTEXT CContainer::GetCertificate()
{
	PCCERT_CONTEXT pCertContext = CertDuplicateCertificateContext(_pCertContext);
	return pCertContext;
}

BOOL CContainer::Erase()
{
	HCRYPTPROV hProv;
	return CryptAcquireContext(&hProv,
					_szContainerName,
					_szProviderName,
					PROV_RSA_FULL,
					CRYPT_DELETEKEYSET);
}

BOOL CContainer::IsOnReader(LPCTSTR szReaderName)
{
	return _tcscmp(_szReaderName,szReaderName) == 0;
}

PEID_SMARTCARD_CSP_INFO CContainer::GetCSPInfo()
{
	DWORD dwReaderLen = (DWORD) _tcslen(_szReaderName)+1;
	DWORD dwCardLen = (DWORD) _tcslen(_szCardName)+1;
	DWORD dwProviderLen = (DWORD) _tcslen(_szProviderName)+1;
	DWORD dwContainerLen = (DWORD) _tcslen(_szContainerName)+1;
	DWORD dwBufferSize = dwReaderLen + dwCardLen + dwProviderLen + dwContainerLen;
	
	PEID_SMARTCARD_CSP_INFO pCspInfo = (PEID_SMARTCARD_CSP_INFO) EIDAlloc(sizeof(EID_SMARTCARD_CSP_INFO)+dwBufferSize*sizeof(TCHAR));
	if (!pCspInfo) return NULL;
	//ZeroMemory(pCspInfo);
	memset(pCspInfo,0,sizeof(EID_SMARTCARD_CSP_INFO));
	pCspInfo->dwCspInfoLen = sizeof(EID_SMARTCARD_CSP_INFO)+dwBufferSize*sizeof(TCHAR);
	pCspInfo->MessageType = 1;
	pCspInfo->KeySpec = _KeySpec;
	pCspInfo->nCardNameOffset = ARRAYSIZE(pCspInfo->bBuffer);
	pCspInfo->nReaderNameOffset = pCspInfo->nCardNameOffset + dwCardLen;
	pCspInfo->nContainerNameOffset = pCspInfo->nReaderNameOffset + dwReaderLen;
	pCspInfo->nCSPNameOffset = pCspInfo->nContainerNameOffset + dwContainerLen;
	memset(pCspInfo->bBuffer,0,sizeof(pCspInfo->bBuffer));
	_tcscpy_s(&pCspInfo->bBuffer[pCspInfo->nCardNameOffset] ,dwBufferSize + 4 - pCspInfo->nCardNameOffset, _szCardName);
	_tcscpy_s(&pCspInfo->bBuffer[pCspInfo->nReaderNameOffset] ,dwBufferSize + 4 - pCspInfo->nReaderNameOffset, _szReaderName);
	_tcscpy_s(&pCspInfo->bBuffer[pCspInfo->nContainerNameOffset] ,dwBufferSize + 4 - pCspInfo->nContainerNameOffset, _szContainerName);
	_tcscpy_s(&pCspInfo->bBuffer[pCspInfo->nCSPNameOffset] ,dwBufferSize + 4 - pCspInfo->nCSPNameOffset, _szProviderName);
	return pCspInfo;
}

void CContainer::FreeCSPInfo(PEID_SMARTCARD_CSP_INFO pCspInfo)
{
	EIDFree(pCspInfo);
}

BOOL CContainer::ViewCertificate(HWND hWnd)
{
	CRYPTUI_VIEWCERTIFICATE_STRUCT certViewInfo;
	BOOL fPropertiesChanged = FALSE;
	LPCSTR					szOid;
	certViewInfo.dwSize = sizeof(CRYPTUI_VIEWCERTIFICATE_STRUCT);
	certViewInfo.hwndParent = hWnd;
	certViewInfo.dwFlags = CRYPTUI_DISABLE_EDITPROPERTIES | CRYPTUI_DISABLE_ADDTOSTORE | CRYPTUI_DISABLE_EXPORT | CRYPTUI_DISABLE_HTMLLINK;
	certViewInfo.szTitle = TEXT("Info");
	certViewInfo.pCertContext = _pCertContext;
	certViewInfo.cPurposes = 0;
	certViewInfo.rgszPurposes = 0;
	if (!GetPolicyValue(AllowCertificatesWithNoEKU))
	{
		certViewInfo.cPurposes = 1;
		szOid = szOID_KP_SMARTCARD_LOGON;
		certViewInfo.rgszPurposes = & szOid;
	}
	certViewInfo.pCryptProviderData = NULL;
	certViewInfo.hWVTStateData = NULL;
	certViewInfo.fpCryptProviderDataTrustedUsage = FALSE;
	certViewInfo.idxSigner = 0;
	certViewInfo.idxCert = 0;
	certViewInfo.fCounterSigner = FALSE;
	certViewInfo.idxCounterSigner = 0;
	certViewInfo.cStores = 0;
	certViewInfo.rghStores = NULL;
	certViewInfo.cPropSheetPages = 0;
	certViewInfo.rgPropSheetPages = NULL;
	certViewInfo.nStartPage = 0;
	
	return CryptUIDlgViewCertificate(&certViewInfo,&fPropertiesChanged);
}

BOOL CContainer::TriggerRemovePolicy()
{
	LONG lResult;
	BOOL fReturn = FALSE;
	HKEY hRemovePolicyKey = NULL;
	PBYTE pbBuffer = NULL;
	DWORD dwSize;
	DWORD dwProcessId, dwSessionId;
	TCHAR szValueKey[sizeof(DWORD)+1];
	SC_HANDLE hService = NULL;
	SC_HANDLE hServiceManager = NULL;
	SERVICE_STATUS ServiceStatus;

	EIDCardLibraryTrace(WINEVENT_LEVEL_INFO,L"Enter");
	if (!_ActivityCount)
	{
		EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Activity Count = 0");
		return FALSE;
	}
	__try
	{

		dwProcessId = GetCurrentProcessId();
		if (!ProcessIdToSessionId(dwProcessId, &dwSessionId))
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"ProcessIdToSessionId 0x%08x",GetLastError());
			__leave;
		}
		lResult = RegOpenKey(HKEY_LOCAL_MACHINE, REMOVALPOLICYKEY ,&hRemovePolicyKey);
		if (lResult !=ERROR_SUCCESS)
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"RegOpenKey 0x%08x (service not running ?)",lResult);
			__leave;
		}
		dwSize = (DWORD) (sizeof(USHORT) + sizeof(USHORT) + (_tcslen(_szReaderName) + 1) *sizeof(WCHAR));
		pbBuffer = (PBYTE) EIDAlloc(dwSize);
		if (!pbBuffer)
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"EIDAlloc 0x%08x",GetLastError());
			__leave;
		}
#ifdef UNICODE
		wcscpy_s((PWSTR)pbBuffer, wcslen(_szReaderName) + 1, _szReaderName);
#else
		MultiByteToWideChar(CP_ACP, 0, _szReaderName, _tcslen(_szReaderName) + 1, pbBuffer, _tcslen(_szReaderName) + 1);
#endif
		*(PUSHORT)(pbBuffer + dwSize - sizeof(USHORT)) = _ActivityCount;
		*(PUSHORT)(pbBuffer + dwSize - 2*sizeof(USHORT)) = 0;

		_stprintf_s(szValueKey, sizeof(DWORD)+1, TEXT("%d"),dwSessionId);

		lResult = RegSetValueEx (hRemovePolicyKey, szValueKey, 0, REG_BINARY, pbBuffer, dwSize);
		if (lResult !=ERROR_SUCCESS)
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"RegSetValue 0x%08x (not enough privilege ?)",lResult);
			__leave;
		}
		// restart service
		hServiceManager = OpenSCManager(NULL,NULL,SC_MANAGER_CONNECT);
		if (!hServiceManager)
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"OpenSCManager 0x%08x",GetLastError());
			__leave;
		}
		hService = OpenService(hServiceManager, TEXT("ScPolicySvc"), SERVICE_START | SERVICE_STOP | SERVICE_QUERY_STATUS);
		if (!hService)
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"OpenService 0x%08x",GetLastError());
			__leave;
		}
		if (!ControlService(hService,SERVICE_CONTROL_STOP,&ServiceStatus))
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"ControlService 0x%08x",GetLastError());
			__leave;
		}
		//Boucle d'attente de l'arret
		do{
			if (!QueryServiceStatus(hService,&ServiceStatus))
			{
				EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"QueryServiceStatus 0x%08x",GetLastError());
				__leave;
			}
			Sleep(100);
		} while(ServiceStatus.dwCurrentState != SERVICE_STOPPED); 

		if (!StartService(hService,0,NULL))
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"StartService 0x%08x",GetLastError());
			__leave;
		}
		fReturn = TRUE;
	}
	__finally
	{
		if (hService)
			CloseServiceHandle(hService);
		if (hServiceManager)
			CloseServiceHandle(hServiceManager);
		if (pbBuffer)
			EIDFree(pbBuffer);
		if (hRemovePolicyKey)
			RegCloseKey(hRemovePolicyKey);
	}
	return fReturn;
}