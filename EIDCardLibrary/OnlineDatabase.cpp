#include <Windows.h>
#include <tchar.h>
#include <stdio.h>
#include <Winhttp.h>

#include "CertificateUtilities.h"
#include "Tracing.h"

#pragma comment(lib,"Version.lib")
#pragma comment(lib,"Winhttp.lib")
#pragma comment(lib,"Wininet.lib")

extern "C"
{
	// wininet and winhttp conflicts
	BOOLAPI
	InternetCanonicalizeUrlA(
		__in LPCSTR lpszUrl,
		__out_ecount(*lpdwBufferLength) LPSTR lpszBuffer,
		__inout LPDWORD lpdwBufferLength,
		__in DWORD dwFlags
		);
	BOOLAPI
	InternetCanonicalizeUrlW(
		__in LPCWSTR lpszUrl,
		__out_ecount(*lpdwBufferLength) LPWSTR lpszBuffer,
		__inout LPDWORD lpdwBufferLength,
		__in DWORD dwFlags
		);
	#ifdef UNICODE
	#define InternetCanonicalizeUrl  InternetCanonicalizeUrlW
	#else
	#define InternetCanonicalizeUrl  InternetCanonicalizeUrlA
	#endif // !UNICODE
}

BOOL PostDataToTheSupportSite(PSTR szPostData)
{
	HINTERNET hSession = NULL;
	HINTERNET hConnect = NULL;
	HINTERNET hRequest = NULL;
	DWORD dwError = 0;
	BOOL fReturn = FALSE;
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
		// WINHTTP_FLAG_SECURE
		hRequest = WinHttpOpenRequest(hConnect,TEXT("POST"),TEXT("/support/submitReport.aspx"),NULL,WINHTTP_NO_REFERER,WINHTTP_DEFAULT_ACCEPT_TYPES,0);
		if (!hRequest)
		{
			dwError = GetLastError();
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Failed WinHttpOpenRequest 0x%08X",dwError);
			__leave;
		}
		LPCTSTR additionalHeaders = TEXT("Content-Type: application/x-www-form-urlencoded\r\n");
		if (!WinHttpSendRequest(hRequest, additionalHeaders, (DWORD) -1, (LPVOID)szPostData, (DWORD) strlen(szPostData), (DWORD) strlen(szPostData), 0))
		{
			dwError = GetLastError();
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Failed WinHttpSendRequest 0x%08X",dwError);
			__leave;
		}
		fReturn = TRUE;
	}
	__finally
	{
		if (hSession)
			WinHttpCloseHandle(hSession);
	}
	SetLastError(dwError);
	return fReturn;
}


void UrlEncoder(__inout PCHAR *ppPointer, __inout PDWORD pdwRemainingSize, __in PTSTR szInput, _In_opt_ BOOL DoNotEscape = FALSE)
{
	if (!szInput) return;
	while(*szInput != L'\0')
	{
		if (
			(
				((*szInput >= L'A' && *szInput <= L'Z') 
					|| (*szInput >= L'a' && *szInput <= L'z')
					|| (*szInput >= L'0' && *szInput <= L'9')
					|| (*szInput == L'-') || (*szInput == L'_') || (*szInput == L'.') || (*szInput == L'~'))
				|| DoNotEscape) 
			&& *pdwRemainingSize > 1)
		{
			**ppPointer = (CHAR)*szInput;
			(*ppPointer)++;
			(*pdwRemainingSize)--;
		}
		else if (*szInput < 256 && *pdwRemainingSize > 3)
		{
			sprintf_s(*ppPointer, *pdwRemainingSize, "%%%02X",*szInput);
			(*ppPointer)+=3;
			(*pdwRemainingSize)-=3;
		}
		else if (*pdwRemainingSize > 6)
		{
			sprintf_s(*ppPointer, *pdwRemainingSize, "%%u%04X",*szInput);
			(*ppPointer)+=6;
			(*pdwRemainingSize)-=6;
		}
		szInput++;
	}
	**ppPointer = '\0';
}

void UrlLogFileEncoder(__inout PCHAR *ppPointer, __inout PDWORD pdwRemainingSize, __in PTSTR szTracingFile)
{
	HANDLE hFile = INVALID_HANDLE_VALUE;
	BYTE pbBuffer[256];
	BOOL bResult;
	DWORD dwByteRead;
	__try
	{
		hFile = CreateFile(szTracingFile, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
		if (hFile == INVALID_HANDLE_VALUE)
		{
			__leave;
		}
		bResult = ReadFile(hFile, pbBuffer, ARRAYSIZE(pbBuffer), &dwByteRead, NULL);
		while (! (bResult &&  dwByteRead == 0) )
		{
			for(DWORD i = 0; i< dwByteRead; i++)
			{
				if (((pbBuffer[i] >= L'A' && pbBuffer[i] <= L'Z') 
							|| (pbBuffer[i] >= L'a' && pbBuffer[i] <= L'z')
							|| (pbBuffer[i] >= L'0' && pbBuffer[i] <= L'9')
							|| (pbBuffer[i] == L'-') || (pbBuffer[i] == L'_') || (pbBuffer[i] == L'.') || (pbBuffer[i] == L'~'))
					&& *pdwRemainingSize > 1)
				{
					**ppPointer = (CHAR)pbBuffer[i];
					(*ppPointer)++;
					(*pdwRemainingSize)--;
				}
				else if (*pdwRemainingSize > 3)
				{
					sprintf_s(*ppPointer, *pdwRemainingSize, "%%%02X",pbBuffer[i]);
					(*ppPointer)+=3;
					(*pdwRemainingSize)-=3;
				}
			}
			bResult = ReadFile(hFile, pbBuffer, ARRAYSIZE(pbBuffer), &dwByteRead, NULL);
		}
	}
	__finally
	{
		if (hFile != INVALID_HANDLE_VALUE)
			CloseHandle(hFile);
	}
	**ppPointer = '\0';
}
BOOL CommunicateTestNotOK(DWORD dwErrorCode, PTSTR szEmail, PTSTR szTracingFile)
{
	BOOL fReturn = FALSE;
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
	CHAR szPostData[1000000]= "";
	DWORD dwRemainingSize = ARRAYSIZE(szPostData);
	PCHAR ppPointer = szPostData;

	if (!AskForCard(szReaderName,256,szCardName,256))
	{
		return FALSE;
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

	UrlEncoder(&ppPointer, &dwRemainingSize, TEXT("hardwareInfo="), TRUE);
	UrlEncoder(&ppPointer, &dwRemainingSize, szHardwareInfo);
	UrlEncoder(&ppPointer, &dwRemainingSize, TEXT("&osInfo="), TRUE);
	UrlEncoder(&ppPointer, &dwRemainingSize, szOsInfo);
	UrlEncoder(&ppPointer, &dwRemainingSize, TEXT("&ReaderName="), TRUE);
	UrlEncoder(&ppPointer, &dwRemainingSize, szReaderName);
	UrlEncoder(&ppPointer, &dwRemainingSize, TEXT("&CardName="), TRUE);
	UrlEncoder(&ppPointer, &dwRemainingSize, szCardName);
	UrlEncoder(&ppPointer, &dwRemainingSize, TEXT("&ProviderName="), TRUE);
	UrlEncoder(&ppPointer, &dwRemainingSize, szProviderName);
	UrlEncoder(&ppPointer, &dwRemainingSize, TEXT("&ATR="), TRUE);
	UrlEncoder(&ppPointer, &dwRemainingSize, szATR);
	UrlEncoder(&ppPointer, &dwRemainingSize, TEXT("&ATRMask="), TRUE);
	UrlEncoder(&ppPointer, &dwRemainingSize, szATRMask);
	UrlEncoder(&ppPointer, &dwRemainingSize, TEXT("&CspDll="), TRUE);
	UrlEncoder(&ppPointer, &dwRemainingSize, szCspDll);
	UrlEncoder(&ppPointer, &dwRemainingSize, TEXT("&FileVersion="), TRUE);
	UrlEncoder(&ppPointer, &dwRemainingSize, szFileVersion);
	UrlEncoder(&ppPointer, &dwRemainingSize, TEXT("&Company="), TRUE);
	UrlEncoder(&ppPointer, &dwRemainingSize, szCompany);
	UrlEncoder(&ppPointer, &dwRemainingSize, TEXT("&ErrorCode="), TRUE);
	TCHAR szErrorCode[16];
	_stprintf_s(szErrorCode, ARRAYSIZE(szErrorCode),TEXT("0x%08X"),dwErrorCode);
	UrlEncoder(&ppPointer, &dwRemainingSize, szErrorCode);
	if (szEmail != NULL)
	{
		UrlEncoder(&ppPointer, &dwRemainingSize, TEXT("&Email="), TRUE);
		UrlEncoder(&ppPointer, &dwRemainingSize, szEmail);
	}
	if (szTracingFile != NULL)
	{
		UrlEncoder(&ppPointer, &dwRemainingSize, TEXT("&LogFile="), TRUE);
		UrlLogFileEncoder(&ppPointer, &dwRemainingSize, szTracingFile);
	}
	fReturn = PostDataToTheSupportSite(szPostData);
	return fReturn;
}

BOOL CommunicateTestOK()
{
	return CommunicateTestNotOK(0, NULL, NULL);
}
