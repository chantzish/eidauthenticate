
#include <windows.h>
#include <tchar.h>
#include <Cryptuiapi.h>

#include "EIDCardLibrary.h"
#include "Tracing.h"
#include "CContainer.h"
#include "CertificateValidation.h"

#pragma comment(lib, "Cryptui.lib")

#define REMOVALPOLICYKEY TEXT("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Removal Policy")

CContainer::CContainer(LPCTSTR szReaderName, LPCTSTR szCardName, LPCTSTR szProviderName, LPCTSTR szContainerName, DWORD KeySpec,__in USHORT ActivityCount,PCCERT_CONTEXT pCertContext)
{
	_szReaderName = new TCHAR[_tcslen(szReaderName)+1];
	_tcscpy_s(_szReaderName,_tcslen(szReaderName)+1,szReaderName);
	_szProviderName = new TCHAR[_tcslen(szProviderName)+1];
	_tcscpy_s(_szProviderName,_tcslen(szProviderName)+1,szProviderName);
	_szContainerName = new TCHAR[_tcslen(szContainerName)+1];
	_tcscpy_s(_szContainerName,_tcslen(szContainerName)+1,szContainerName);
	_szCardName = new TCHAR[_tcslen(szCardName)+1];
	_tcscpy_s(_szCardName,_tcslen(szCardName)+1,szCardName);
	//_szUserName = new TCHAR[_tcslen(szContainerName)+1];
	//_tcscpy_s(_szUserName,_tcslen(szContainerName)+1,szContainerName);
	_KeySpec = KeySpec;
	_ActivityCount = ActivityCount;
	_pCertContext = pCertContext;
}

CContainer::~CContainer()
{
	delete[] _szReaderName;
	delete[] _szCardName;
	delete[] _szProviderName;
	delete[] _szContainerName;
	if (_szUserName) delete[] _szUserName;
	if (_pCertContext) {
		CertFreeCertificateContext(_pCertContext);
	}
}

PTSTR CContainer::GetUserName()
{
	_szUserName = GetUserNameFromCertificate(_pCertContext);
	return _szUserName;
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

PCCERT_CONTEXT CContainer::GetContainer()
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
	DWORD dwReaderLen = _tcslen(_szReaderName)+1;
	DWORD dwCardLen = _tcslen(_szCardName)+1;
	DWORD dwProviderLen = _tcslen(_szProviderName)+1;
	DWORD dwContainerLen = _tcslen(_szContainerName)+1;
	DWORD dwBufferSize = dwReaderLen + dwCardLen + dwProviderLen + dwContainerLen;
	
	PEID_SMARTCARD_CSP_INFO pCspInfo = (PEID_SMARTCARD_CSP_INFO) malloc(sizeof(EID_SMARTCARD_CSP_INFO)+dwBufferSize*sizeof(TCHAR));
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
	free(pCspInfo);
}

BOOL CContainer::ViewCertificate(HWND hWnd)
{
	CRYPTUI_VIEWCERTIFICATE_STRUCT certViewInfo;
	BOOL fPropertiesChanged = FALSE;

	certViewInfo.dwSize = sizeof(CRYPTUI_VIEWCERTIFICATE_STRUCT);
	certViewInfo.hwndParent = hWnd;
	certViewInfo.dwFlags = CRYPTUI_DISABLE_EDITPROPERTIES | CRYPTUI_DISABLE_ADDTOSTORE | CRYPTUI_DISABLE_EXPORT | CRYPTUI_DISABLE_HTMLLINK;
	certViewInfo.szTitle = TEXT("Info");
	certViewInfo.pCertContext = _pCertContext;
	certViewInfo.cPurposes = 0;
	certViewInfo.rgszPurposes = 0;
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
		dwSize = sizeof(USHORT) + sizeof(USHORT) + (_tcslen(_szReaderName) + 1) *sizeof(WCHAR);
		pbBuffer = (PBYTE) malloc(dwSize);
		if (!pbBuffer)
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"malloc 0x%08x",GetLastError());
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
			free(pbBuffer);
		if (hRemovePolicyKey)
			RegCloseKey(hRemovePolicyKey);
	}
	return fReturn;
}