#include <Windows.h>
#include <tchar.h>
#include <Winhttp.h>
#include "CertificateUtilities.h"
#include "Tracing.h"

#pragma comment(lib,"Version.lib")
#pragma comment(lib,"Winhttp.lib")

void TryToFindACSP(PTSTR szATR)
{

}


void CommunicateTestNotOK(DWORD dwErrorCode)
{
	TCHAR szReaderName[256] = TEXT("");
	TCHAR szCardName[256] = TEXT("");
	TCHAR szProviderName[256] = TEXT("");
	TCHAR szATR[256] = TEXT("");
	TCHAR szATRMask[256] = TEXT("");
	TCHAR szCspDll[256] = TEXT("");
	TCHAR szOsInfo[256] = TEXT("");
	TCHAR szHardwareInfo[256] = TEXT("");
	TCHAR szFileVersion[256] = TEXT("");
	TCHAR szCompany[256] = TEXT("");
	DWORD dwProviderNameLen = ARRAYSIZE(szProviderName);
	DWORD dwSize;
	if (!AskForCard(szReaderName,256,szCardName,256))
	{
		return;
	}
	SchGetProviderNameFromCardName(szCardName, szProviderName, &dwProviderNameLen);
	HKEY hRegKeyCalais, hRegKeyCSP, hRegKey;
	// smart card info (atr & mask)
	if (!RegOpenKeyEx(HKEY_LOCAL_MACHINE, TEXT("SOFTWARE\\Microsoft\\Cryptography\\Calais\\SmartCards"), 0, KEY_READ, &hRegKeyCalais))
	{
		BYTE bATR[100];
		DWORD dwSize = sizeof(bATR);
		if (!RegOpenKeyEx(hRegKeyCalais, szCardName, 0, KEY_READ, &hRegKey))
		{
			RegQueryValueEx(hRegKey,TEXT("ATR"), NULL, NULL,(PBYTE)&bATR,&dwSize);
			for(DWORD i=0; i< dwSize; i++)
			{
				_stprintf_s(szATR + 2*i, ARRAYSIZE(szATR) - 2*i,TEXT("%02X"),bATR[i]);
			}
			dwSize = sizeof(bATR);
			RegQueryValueEx(hRegKey,TEXT("ATRMask"), NULL, NULL,(PBYTE)&bATR,&dwSize);
			for(DWORD i=0; i< dwSize; i++)
			{
				_stprintf_s(szATRMask + 2*i, ARRAYSIZE(szATRMask) - 2*i,TEXT("%02X"),bATR[i]);
			}
			if (_tcscmp(TEXT("Microsoft Base Smart Card Crypto Provider"), szProviderName) == 0)
			{
				dwSize = sizeof(szCspDll);
				RegQueryValueEx(hRegKey,TEXT("80000001"), NULL, NULL,(PBYTE)&szCspDll,&dwSize);
			}
			RegCloseKey(hRegKey);
		}
		RegCloseKey(hRegKeyCalais);
	}
	if (szCspDll[0] == 0)
	{
		// csp info
		if (!RegOpenKeyEx(HKEY_LOCAL_MACHINE, TEXT("SOFTWARE\\Microsoft\\Cryptography\\Defaults\\Provider"), 0, KEY_READ, &hRegKeyCSP))
		{
			dwSize = sizeof(szCspDll);
			if (!RegOpenKeyEx(hRegKeyCalais, szProviderName, 0, KEY_READ, &hRegKey))
			{
				RegQueryValueEx(hRegKey, TEXT("Image Path"), NULL,NULL,(PBYTE)&szCspDll,&dwSize);
				RegCloseKey(hRegKey);
			}
			RegCloseKey(hRegKeyCalais);
		}
	}
	if (szCspDll[0] != 0)
	{
		DWORD dwHandle;
		dwSize = GetFileVersionInfoSize(szCspDll, &dwHandle);
		if (dwSize)
		{
			UINT uSize;
			PVOID versionInfo = malloc(dwSize);
			PWSTR pszFileVersion = NULL;
			PWSTR pszCompany = NULL;
			if (GetFileVersionInfo(szCspDll, dwHandle, dwSize, versionInfo))
			{
				BOOL retVal; 
				LPVOID version=NULL;
				DWORD vLen,langD;
				TCHAR szfileVersionPath[256];
				retVal = VerQueryValue(versionInfo,TEXT("\\VarFileInfo\\Translation"),&version,(UINT *)&vLen);
				if (retVal && vLen==4) 
				{
					memcpy(&langD,version,4);            
					_stprintf_s(szfileVersionPath, ARRAYSIZE(szfileVersionPath),
								TEXT("\\StringFileInfo\\%02X%02X%02X%02X\\FileVersion"),
							(langD & 0xff00)>>8,langD & 0xff,(langD & 0xff000000)>>24, 
							(langD & 0xff0000)>>16);            
				}
				else 
					_stprintf_s(szfileVersionPath, ARRAYSIZE(szfileVersionPath),
								TEXT("\\StringFileInfo\\%04X04B0\\FileVersion"),
							GetUserDefaultLangID());
				retVal = VerQueryValue(versionInfo,szfileVersionPath,(PVOID*)&pszFileVersion,(UINT *)&uSize);

				if (pszFileVersion != NULL) 
					_stprintf_s(szFileVersion, ARRAYSIZE(szFileVersion),TEXT("%ls"),pszFileVersion);

				if (retVal && vLen==4) 
				{
					memcpy(&langD,version,4);            
					_stprintf_s(szfileVersionPath, ARRAYSIZE(szfileVersionPath),
								TEXT("\\StringFileInfo\\%02X%02X%02X%02X\\CompanyName"),
							(langD & 0xff00)>>8,langD & 0xff,(langD & 0xff000000)>>24, 
							(langD & 0xff0000)>>16);            
				}
				else 
					_stprintf_s(szfileVersionPath, ARRAYSIZE(szfileVersionPath),
								TEXT("\\StringFileInfo\\%04X04B0\\CompanyName"),
							GetUserDefaultLangID());
				retVal = VerQueryValue(versionInfo,szfileVersionPath,(PVOID*)&pszCompany,(UINT *)&uSize);

				if (pszFileVersion != NULL) 
					_stprintf_s(szCompany, ARRAYSIZE(szCompany),TEXT("%ls"),pszCompany);
			}
			free(versionInfo);
		}
	}

	// os version
	OSVERSIONINFOEX version;
	version.dwOSVersionInfoSize = sizeof(version);
	GetVersionEx((LPOSVERSIONINFO )&version);
	_stprintf_s(szOsInfo, ARRAYSIZE(szOsInfo),TEXT("%d.%d.%d;%d;%d.%d;%s"), 
								version.dwMajorVersion, version.dwMinorVersion, 
								version.dwBuildNumber, version.dwPlatformId,
								version.wSuiteMask, version.wProductType, 
								version.szCSDVersion);
	
	// hardware info
	SYSTEM_INFO SystemInfo;
	GetNativeSystemInfo(&SystemInfo);
	_stprintf_s(szHardwareInfo, ARRAYSIZE(szHardwareInfo), TEXT("%u;%u;%u"), 
      SystemInfo.dwNumberOfProcessors, SystemInfo.dwProcessorType, SystemInfo.wProcessorRevision);
}

void CommunicateTestOK()
{
	CommunicateTestNotOK(0);
}

void Communicate()
{
	HINTERNET hSession = NULL;
	HINTERNET hConnect = NULL;
	HINTERNET hRequest = NULL;
	DWORD dwError;
	__try
	{ 
		hSession = WinHttpOpen(TEXT("EIDAuthenticate"), 
				WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, 
				WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
		if (!hSession)
		{
			dwError = GetLastError();
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Failed WinHttpOpen 0x%08X",dwError);
			__leave;
		}
		hConnect = WinHttpConnect(hSession, TEXT("www.mysmartlogon.com"),INTERNET_DEFAULT_PORT, 0);
		if (!hConnect)
		{
			dwError = GetLastError();
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Failed WinHttpConnect 0x%08X",dwError);
			__leave;
		}
		hRequest = WinHttpOpenRequest(hConnect,TEXT("POST"),TEXT("/EID/toto.aspx"),NULL,WINHTTP_NO_REFERER,WINHTTP_DEFAULT_ACCEPT_TYPES,WINHTTP_FLAG_SECURE);
		if (!hRequest)
		{
			dwError = GetLastError();
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Failed WinHttpOpenRequest 0x%08X",dwError);
			__leave;
		}
		LPCTSTR additionalHeaders = TEXT("Content-Type: application/x-www-form-urlencoded\r\n");
		DWORD hLen   = -1;
		//WinHttpSendRequest(hRequest, additionalHeaders, -1, (LPVOID)params, pLen, pLen, 0);
			//WinHttpWriteData
	}
	__finally
	{
		if (hSession)
			WinHttpCloseHandle(hSession);
	}
}