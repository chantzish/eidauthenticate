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