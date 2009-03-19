#include <windows.h>
#include <tchar.h>

#include "GPO.h"
#include "Tracing.h"

#pragma comment(lib,"Advapi32")

/** Used to manage policy key retrieval */

TCHAR szMainGPOKey[] = _T("SOFTWARE\\Policies\\Microsoft\\Windows\\SmartCardCredentialProvider");
TCHAR szWinlogonGPOKey[] = _T("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Policies\\System");
typedef struct _GPOInfo
{
	LPCTSTR Key;
	LPCTSTR Value;
} GPOInfo;

GPOInfo MyGPOInfo[] = 
{
  {szMainGPOKey, _T("AllowSignatureOnlyKeys") },
  {szMainGPOKey, _T("AllowCertificatesWithNoEKU") },
  {szMainGPOKey, _T("AllowTimeInvalidCertificates") },
  {szMainGPOKey, _T("AllowIntegratedUnblock") },
  {szMainGPOKey, _T("ReverseSubject") },
  {szMainGPOKey, _T("X509HintsNeeded") },
  {szMainGPOKey, _T("IntegratedUnblockPromptString") },
  {szMainGPOKey, _T("CertPropEnabledString") },
  {szMainGPOKey, _T("CertPropRootEnabledString") },
  {szMainGPOKey, _T("RootsCleanupOption") },
  {szMainGPOKey, _T("FilterDuplicateCertificates") },
  {szMainGPOKey, _T("ForceReadingAllCertificates") },
  {szWinlogonGPOKey, _T("scforceoption") }
};

DWORD GetPolicyValue(GPOPolicy Policy)
{
	HKEY key;
	DWORD size = sizeof(DWORD);
	DWORD value = 0;
	DWORD type=REG_SZ;
	if (RegOpenKeyEx(HKEY_LOCAL_MACHINE,MyGPOInfo[Policy].Key,NULL, KEY_READ, &key)==ERROR_SUCCESS){
		if (RegQueryValueEx(key,MyGPOInfo[Policy].Value,NULL, &type,(LPBYTE) &value, &size)==ERROR_SUCCESS)
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_INFO,L"Policy %s found = %x",MyGPOInfo[Policy].Value,value);
		}
		else
		{
			value = 0;
			EIDCardLibraryTrace(WINEVENT_LEVEL_INFO,L"Policy %s value not found = %x",MyGPOInfo[Policy].Value,value);
		}
		RegCloseKey(key);
	}
	else
	{
		value = 0;
		EIDCardLibraryTrace(WINEVENT_LEVEL_INFO,L"Policy %s key not found = %x",MyGPOInfo[Policy].Value,value);
		
	}
	return value;
}