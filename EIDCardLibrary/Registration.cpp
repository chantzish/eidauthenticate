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
#define SECURITY_WIN32
#include <sspi.h>

#include "../EIDCardLibrary/EIDCardLibrary.h"
#include "../EIDCardLibrary/guid.h"
#include "../EIDCardLibrary/Tracing.h"


/** Used to append a string to a multi string reg key */
void AppendValueToMultiSz(HKEY hKey,PTSTR szKey, PTSTR szValue, PTSTR szData)
{
	HKEY hkResult;
	DWORD Status;
	Status=RegOpenKeyEx(hKey,szKey,0,KEY_READ|KEY_QUERY_VALUE|KEY_WRITE,&hkResult);
	if (Status != ERROR_SUCCESS) {
		MessageBoxWin32(Status);
		return;
	}
	DWORD RegType;
	DWORD RegSize;
	PTSTR Buffer = NULL;
	PTSTR Pointer;
	RegSize = 0;
	Status = RegQueryValueEx( hkResult,szValue,NULL,&RegType,NULL,&RegSize);
	if (Status != ERROR_SUCCESS) {
		MessageBoxWin32(Status);
		RegCloseKey(hkResult);
		return;
	}
	RegSize += (DWORD) (_tcslen(szData) + 1 ) * sizeof(TCHAR);
	Buffer = (PTSTR) EIDAlloc(RegSize);
	if (!Buffer)
	{
		MessageBoxWin32(GetLastError());
		RegCloseKey(hkResult);
		return;
	}
	Status = RegQueryValueEx( hkResult,szValue,NULL,&RegType,(LPBYTE)Buffer,&RegSize);
	if (Status != ERROR_SUCCESS) {
		MessageBoxWin32(Status);
		RegCloseKey(hkResult);
		EIDFree(Buffer);
		return;
	}

	char bFound = FALSE;
	Pointer = Buffer;
	while (*Pointer) 
	{
		if (_tcscmp(Pointer,szData)==0) {
			bFound = TRUE;
			break;
		}
		Pointer = Pointer + _tcslen(Pointer) + 1;
	}
	if (bFound == FALSE) {
		// add the data
		_tcscpy_s(Pointer, _tcslen(szData) + 1, szData);
		Pointer[_tcslen(szData) + 1] = 0;
		RegSize += (DWORD) (_tcslen(szData) + 1 ) * sizeof(TCHAR);
		Status = RegSetValueEx(hkResult, szValue, 0, RegType, (PBYTE) Buffer, RegSize);
		if (Status != ERROR_SUCCESS) {
			MessageBoxWin32(Status);
		}
	}
	EIDFree(Buffer);
	RegCloseKey(hkResult);
}

/** Used to Remove a string to a multi string reg key */
void RemoveValueFromMultiSz(HKEY hKey, PTSTR szKey, PTSTR szValue, PTSTR szData)
{
	HKEY hkResult;
	DWORD Status;
	Status=RegOpenKeyEx(hKey,szKey,0,KEY_READ|KEY_QUERY_VALUE|KEY_WRITE,&hkResult);
	if (Status != ERROR_SUCCESS) {
		MessageBoxWin32(Status);
		return;
	}
	DWORD RegType;
	DWORD RegSize, RegSizeOut;
	PTSTR BufferIn = NULL;
	PTSTR BufferOut = NULL;
	PTSTR PointerIn;
	PTSTR PointerOut;
	RegSize = 0;
	Status = RegQueryValueEx( hkResult,szValue,NULL,&RegType,NULL,&RegSize);
	if (Status != ERROR_SUCCESS) {
		MessageBoxWin32(Status);
		RegCloseKey(hkResult);
		return;
	}
	BufferIn = (PTSTR) EIDAlloc(RegSize);
	if (!BufferIn)
	{
		MessageBoxWin32(GetLastError());
		RegCloseKey(hkResult);
		return;
	}
	BufferOut = (PTSTR) EIDAlloc(RegSize);
	if (!BufferOut)
	{
		MessageBoxWin32(GetLastError());
		EIDFree(BufferIn);
		RegCloseKey(hkResult);
		return;
	}
	Status = RegQueryValueEx( hkResult,szValue,NULL,&RegType,(LPBYTE)BufferIn,&RegSize);
	if (Status != ERROR_SUCCESS) {
		MessageBoxWin32(Status);
		EIDFree(BufferIn);
		EIDFree(BufferOut);
		RegCloseKey(hkResult);
		return;
	}

	PointerIn = BufferIn;
	PointerOut = BufferOut;
	RegSizeOut = 0;
	
	while (*PointerIn) 
	{
		// copy string if <> szData
		
		if (_tcscmp(PointerIn,szData)!=0) {			
			_tcscpy_s(PointerOut,(RegSize - RegSizeOut) /sizeof(TCHAR), PointerIn);
			RegSizeOut += (DWORD) (_tcslen(PointerOut) + 1) * sizeof(TCHAR);
			PointerOut += _tcslen(PointerOut) + 1;
		}
		PointerIn += _tcslen(PointerIn) + 1;
	}
	
	// last null char
	*PointerOut = 0;
	RegSizeOut += sizeof(TCHAR);
	
	Status = RegSetValueEx(hkResult, szValue, 0, RegType, (PBYTE) BufferOut, RegSizeOut);
	if (Status != ERROR_SUCCESS) {
		MessageBoxWin32(Status);
	}
	
	EIDFree(BufferIn);
	EIDFree(BufferOut);
	RegCloseKey(hkResult);
}

//*************************************************************
//
//  RegDelnodeRecurse()
//
//  Purpose:    Deletes a registry key and all its subkeys / values.
//
//  Parameters: hKeyRoot    -   Root key
//              lpSubKey    -   SubKey to delete
//
//  Return:     TRUE if successful.
//              FALSE if an error occurs.
//
//*************************************************************

BOOL RegDelnodeRecurse (HKEY hKeyRoot, LPTSTR lpSubKey)
{
    LPTSTR lpEnd;
    LONG lResult;
    DWORD dwSize;
    TCHAR szName[MAX_PATH*2];
    HKEY hKey;
    FILETIME ftWrite;

    // First, see if we can delete the key without having
    // to recurse.

    lResult = RegDeleteKey(hKeyRoot, lpSubKey);

    if (lResult == ERROR_SUCCESS) 
        return TRUE;

    lResult = RegOpenKeyEx (hKeyRoot, lpSubKey, 0, KEY_READ, &hKey);

    if (lResult != ERROR_SUCCESS) 
    {
        if (lResult == ERROR_FILE_NOT_FOUND) {
            return TRUE;
        } 
        else {
            return FALSE;
        }
    }

    // Check for an ending slash and add one if it is missing.

    lpEnd = lpSubKey + _tcsclen(lpSubKey);

    if (*(lpEnd - 1) != TEXT('\\')) 
    {
        *lpEnd =  TEXT('\\');
        lpEnd++;
        *lpEnd =  TEXT('\0');
    }

    // Enumerate the keys

    dwSize = MAX_PATH;
    lResult = RegEnumKeyEx(hKey, 0, szName, &dwSize, NULL,
                           NULL, NULL, &ftWrite);

    if (lResult == ERROR_SUCCESS) 
    {
        do {

            _tcscpy_s (lpEnd, MAX_PATH*2 - _tcsclen(lpSubKey), szName);
            if (!RegDelnodeRecurse(hKeyRoot, lpSubKey)) {
                break;
            }
            dwSize = MAX_PATH;
            lResult = RegEnumKeyEx(hKey, 0, szName, &dwSize, NULL,
                                   NULL, NULL, &ftWrite);

        } while (lResult == ERROR_SUCCESS);
    }

    lpEnd--;
    *lpEnd = TEXT('\0');

    RegCloseKey (hKey);

    // Try again to delete the key.

    lResult = RegDeleteKey(hKeyRoot, lpSubKey);

    if (lResult == ERROR_SUCCESS) 
        return TRUE;

    return FALSE;
}

//*************************************************************
//
//  RegDelnode()
//
//  Purpose:    Deletes a registry key and all its subkeys / values.
//
//  Parameters: hKeyRoot    -   Root key
//              lpSubKey    -   SubKey to delete
//
//  Return:     TRUE if successful.
//              FALSE if an error occurs.
//
//*************************************************************

BOOL RegDelnode (HKEY hKeyRoot, LPTSTR lpSubKey)
{
    TCHAR szDelKey[MAX_PATH*2];

    _tcscpy_s(szDelKey, MAX_PATH*2, lpSubKey);
    return RegDelnodeRecurse(hKeyRoot, szDelKey);

}

// to compil with windows XP
#if WINVER < 0x600

LONG WINAPI RegSetKeyValueXP(
  __in      HKEY hKey,
  __in_opt  LPCTSTR lpSubKey,
  __in_opt  LPCTSTR lpValueName,
  __in      DWORD dwType,
  __in_opt  LPCVOID lpData,
  __in      DWORD cbData
)
{
	HKEY hTempKey;
	LONG lResult;
	lResult = RegCreateKeyEx(hKey, lpSubKey, 0,NULL,0,KEY_WRITE, NULL,&hTempKey,NULL);
	if (lResult != ERROR_SUCCESS) return lResult;
	lResult = RegSetValueEx( hTempKey,lpValueName,0, dwType,  (PBYTE) lpData,cbData);
	RegCloseKey(hKey);
	return lResult;
}
#define RegSetKeyValue RegSetKeyValueXP
#endif

void RegisterTheSecurityPackage()
{
	NTSTATUS Status;
	DWORD dwNbPackage;
	PSecPkgInfo pPackageInfo;
	BOOL fFound = FALSE;
	__try
	{
		
		EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Starting...");
		Status = EnumerateSecurityPackages(&dwNbPackage, &pPackageInfo);
		if (Status != SEC_E_OK)
		{
			__leave;
		}
		for(DWORD dwI = 0; dwI < dwNbPackage; dwI++)
		{
			PTSTR szPackage = pPackageInfo[dwI].Name;
			if (_tcscmp(szPackage, AUTHENTICATIONPACKAGENAMET) == 0)
			{
				fFound = TRUE;
			}
		}
		FreeContextBuffer(pPackageInfo);
		if (fFound)
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"The security package was loaded before");
			__leave;
		}
		SECURITY_PACKAGE_OPTIONS options = {sizeof(SECURITY_PACKAGE_OPTIONS)};
		Status = AddSecurityPackage(AUTHENTICATIONPACKAGENAMET, &options);
		if (Status != SEC_E_OK)
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Unable to register the package 0x%08X 0x%08X",Status, GetLastError());
			__leave;
		}
		EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Sucessfully registered the package");
	}
	__finally
	{
	}	
}

/** Installation and uninstallation routine
*/

void EIDAuthenticationPackageDllRegister()
{
	AppendValueToMultiSz(HKEY_LOCAL_MACHINE, TEXT("SYSTEM\\CurrentControlSet\\Control\\Lsa"), TEXT("Security Packages"), AUTHENTICATIONPACKAGENAMET);
	RegisterTheSecurityPackage();
}

void EIDAuthenticationPackageDllUnRegister()
{
	RemoveValueFromMultiSz(HKEY_LOCAL_MACHINE, TEXT("SYSTEM\\CurrentControlSet\\Control\\Lsa"), TEXT("Security Packages"), AUTHENTICATIONPACKAGENAMET);
}

void EIDPasswordChangeNotificationDllRegister()
{
	AppendValueToMultiSz(HKEY_LOCAL_MACHINE, TEXT("SYSTEM\\CurrentControlSet\\Control\\Lsa"), TEXT("Notification Packages"), TEXT("EIDPasswordChangeNotification"));
}

void EIDPasswordChangeNotificationDllUnRegister()
{
	RemoveValueFromMultiSz(HKEY_LOCAL_MACHINE, TEXT("SYSTEM\\CurrentControlSet\\Control\\Lsa"), TEXT("Notification Packages"), TEXT("EIDPasswordChangeNotification"));
}


void EIDCredentialProviderDllRegister()
{
	RegSetKeyValue(	HKEY_LOCAL_MACHINE, 
		TEXT("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Authentication\\Credential Providers\\{B4866A0A-DB08-4835-A26F-414B46F3244C}"), 
		NULL, REG_SZ, TEXT("EidCredentialProvider"),sizeof(TEXT("EidCredentialProvider")));
	RegSetKeyValue(	HKEY_LOCAL_MACHINE, 
		TEXT("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Authentication\\Credential Provider Filters\\{B4866A0A-DB08-4835-A26F-414B46F3244C}"), 
		NULL, REG_SZ, TEXT("EidCredentialProvider"),sizeof(TEXT("EidCredentialProvider")));
	RegSetKeyValue(	HKEY_CLASSES_ROOT, 
		TEXT("CLSID\\{B4866A0A-DB08-4835-A26F-414B46F3244C}"), 
		NULL, REG_SZ, TEXT("EidCredentialProvider"),sizeof(TEXT("EidCredentialProvider")));
	RegSetKeyValue(	HKEY_CLASSES_ROOT, 
		TEXT("CLSID\\{B4866A0A-DB08-4835-A26F-414B46F3244C}\\InprocServer32"),
		NULL, REG_SZ, TEXT("EidCredentialProvider.dll"),sizeof(TEXT("EidCredentialProvider.dll")));
	RegSetKeyValue(	HKEY_CLASSES_ROOT, 
		TEXT("CLSID\\{B4866A0A-DB08-4835-A26F-414B46F3244C}\\InprocServer32"),
		TEXT("ThreadingModel"),REG_SZ, TEXT("Apartment"),sizeof(TEXT("Apartment")));
}

BOOL LsaEIDRemoveAllStoredCredential();

void EIDCredentialProviderDllUnRegister()
{
	RegDelnode(HKEY_CLASSES_ROOT, TEXT("CLSID\\{B4866A0A-DB08-4835-A26F-414B46F3244C}"));
	RegDelnode(HKEY_LOCAL_MACHINE, 
		TEXT("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Authentication\\Credential Providers\\{B4866A0A-DB08-4835-A26F-414B46F3244C}"));
	RegDelnode(HKEY_LOCAL_MACHINE, 
		TEXT("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Authentication\\Credential Provider Filters\\{B4866A0A-DB08-4835-A26F-414B46F3244C}"));
	LsaEIDRemoveAllStoredCredential();
}

void EIDConfigurationWizardDllRegister()
{
	RegSetKeyValue(	HKEY_LOCAL_MACHINE, 
		TEXT("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ControlPanel\\NameSpace\\{F5D846B4-14B0-11DE-B23C-27A355D89593}"),
		NULL,REG_SZ, TEXT("EIDConfigurationWizard"),sizeof(TEXT("EIDConfigurationWizard")));
	RegSetKeyValue(	HKEY_CLASSES_ROOT, 
		TEXT("CLSID\\{F5D846B4-14B0-11DE-B23C-27A355D89593}"), 
		NULL, REG_SZ, TEXT("EIDConfigurationWizard"),sizeof(TEXT("EIDConfigurationWizard")));
	RegSetKeyValue(	HKEY_CLASSES_ROOT, 
		TEXT("CLSID\\{F5D846B4-14B0-11DE-B23C-27A355D89593}"),
		TEXT("System.ApplicationName"),REG_SZ, TEXT("EID.EIDConfigurationWizard"),sizeof(TEXT("EID.EIDConfigurationWizard")));
	RegSetKeyValue(	HKEY_CLASSES_ROOT, 
		TEXT("CLSID\\{F5D846B4-14B0-11DE-B23C-27A355D89593}"),
		TEXT("System.ControlPanel.Category"),REG_SZ, TEXT("10"),sizeof(TEXT("10")));
	RegSetKeyValue(	HKEY_CLASSES_ROOT, 
		TEXT("CLSID\\{F5D846B4-14B0-11DE-B23C-27A355D89593}"),
		TEXT("LocalizedString"),REG_EXPAND_SZ, TEXT("Smart Card Logon"),sizeof(TEXT("Smart Card Logon")));
	RegSetKeyValue(	HKEY_CLASSES_ROOT, 
		TEXT("CLSID\\{F5D846B4-14B0-11DE-B23C-27A355D89593}"),
		TEXT("InfoTip"),REG_EXPAND_SZ, TEXT("Smart Card Logon"),sizeof(TEXT("Smart Card Logon")));
	RegSetKeyValue(	HKEY_CLASSES_ROOT, 
		TEXT("CLSID\\{F5D846B4-14B0-11DE-B23C-27A355D89593}\\DefaultIcon"),
		NULL,REG_EXPAND_SZ, TEXT("%SystemRoot%\\system32\\imageres.dll,-58"),
			sizeof(TEXT("%SystemRoot%\\system32\\imageres.dll,-58")));
	RegSetKeyValue(	HKEY_CLASSES_ROOT, 
		TEXT("CLSID\\{F5D846B4-14B0-11DE-B23C-27A355D89593}\\Shell\\Open\\Command"),
		NULL,REG_EXPAND_SZ, TEXT("%SystemRoot%\\system32\\EIDConfigurationWizard.exe"),
			sizeof(TEXT("%SystemRoot%\\system32\\EIDConfigurationWizard.exe")));
	RegSetKeyValue(	HKEY_CLASSES_ROOT, 
		TEXT("CLSID\\{F5D846B4-14B0-11DE-B23C-27A355D89593}"),
		TEXT("System.Software.TasksFileUrl"),REG_SZ, TEXT("%SystemRoot%\\system32\\EIDConfigurationWizard.exe,-68"),sizeof(TEXT("%SystemRoot%\\system32\\EIDConfigurationWizard.exe,-68")));
	

}

void EIDConfigurationWizardDllUnRegister()
{
	RegDelnode(HKEY_LOCAL_MACHINE, TEXT("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ControlPanel\\NameSpace\\{F5D846B4-14B0-11DE-B23C-27A355D89593}"));
	RegDelnode(HKEY_CLASSES_ROOT, TEXT("CLSID\\{F5D846B4-14B0-11DE-B23C-27A355D89593}"));
}

void EnableLogging()
{
	DWORD64 qdwValue;
	DWORD dwValue;
	LONG err;

	err = RegSetKeyValue(	HKEY_LOCAL_MACHINE, 
		TEXT("SYSTEM\\CurrentControlSet\\Control\\WMI\\Autologger\\EIDCredentialProvider"), 
		TEXT("Guid"), REG_SZ, TEXT("{B4866A0A-DB08-4835-A26F-414B46F3244C}"),sizeof(TEXT("{B4866A0A-DB08-4835-A26F-414B46F3244C}")));
	if (err != ERROR_SUCCESS) {MessageBoxWin32(err); return;}
	err = RegSetKeyValue(	HKEY_LOCAL_MACHINE, 
		TEXT("SYSTEM\\CurrentControlSet\\Control\\WMI\\Autologger\\EIDCredentialProvider"), 
		TEXT("FileName"), REG_SZ, TEXT("c:\\windows\\system32\\LogFiles\\WMI\\EIDCredentialProvider.etl"),sizeof(TEXT("c:\\windows\\system32\\LogFiles\\WMI\\EIDCredentialProvider.etl")));
	if (err != ERROR_SUCCESS) {MessageBoxWin32(err); return;}
	dwValue = 8;
	err = RegSetKeyValue(	HKEY_LOCAL_MACHINE, 
		TEXT("SYSTEM\\CurrentControlSet\\Control\\WMI\\Autologger\\EIDCredentialProvider"), 
		TEXT("FileMax"), REG_DWORD,&dwValue,sizeof(DWORD));
	if (err != ERROR_SUCCESS) {MessageBoxWin32(err); return;}
	dwValue = 1;
	err = RegSetKeyValue(	HKEY_LOCAL_MACHINE, 
		TEXT("SYSTEM\\CurrentControlSet\\Control\\WMI\\Autologger\\EIDCredentialProvider"), 
		TEXT("Start"), REG_DWORD,&dwValue,sizeof(DWORD));
	if (err != ERROR_SUCCESS) {MessageBoxWin32(err); return;}
	dwValue = 8;
	err = RegSetKeyValue(	HKEY_LOCAL_MACHINE, 
		TEXT("SYSTEM\\CurrentControlSet\\Control\\WMI\\Autologger\\EIDCredentialProvider"), 
		TEXT("BufferSize"), REG_DWORD,&dwValue,sizeof(DWORD));
	if (err != ERROR_SUCCESS) {MessageBoxWin32(err); return;}
	dwValue = 0;
	err = RegSetKeyValue(	HKEY_LOCAL_MACHINE, 
		TEXT("SYSTEM\\CurrentControlSet\\Control\\WMI\\Autologger\\EIDCredentialProvider"), 
		TEXT("FlushTimer"), REG_DWORD,&dwValue,sizeof(DWORD));
	if (err != ERROR_SUCCESS) {MessageBoxWin32(err); return;}
	dwValue = 0;
	err = RegSetKeyValue(	HKEY_LOCAL_MACHINE, 
		TEXT("SYSTEM\\CurrentControlSet\\Control\\WMI\\Autologger\\EIDCredentialProvider"), 
		TEXT("MaximumBuffers"), REG_DWORD,&dwValue,sizeof(DWORD));
	if (err != ERROR_SUCCESS) {MessageBoxWin32(err); return;}
	dwValue = 0;
	err = RegSetKeyValue(	HKEY_LOCAL_MACHINE, 
		TEXT("SYSTEM\\CurrentControlSet\\Control\\WMI\\Autologger\\EIDCredentialProvider"), 
		TEXT("MinimumBuffers"), REG_DWORD,&dwValue,sizeof(DWORD));
	if (err != ERROR_SUCCESS) {MessageBoxWin32(err); return;}
	dwValue = 1;
	err = RegSetKeyValue(	HKEY_LOCAL_MACHINE, 
		TEXT("SYSTEM\\CurrentControlSet\\Control\\WMI\\Autologger\\EIDCredentialProvider"), 
		TEXT("ClockType"), REG_DWORD,&dwValue,sizeof(DWORD));
	if (err != ERROR_SUCCESS) {MessageBoxWin32(err); return;}
	dwValue = 64;
	err = RegSetKeyValue(	HKEY_LOCAL_MACHINE, 
		TEXT("SYSTEM\\CurrentControlSet\\Control\\WMI\\Autologger\\EIDCredentialProvider"), 
		TEXT("MaxFileSize"), REG_DWORD,&dwValue,sizeof(DWORD));
	if (err != ERROR_SUCCESS) {MessageBoxWin32(err); return;}
	dwValue = 4864;
	err = RegSetKeyValue(	HKEY_LOCAL_MACHINE, 
		TEXT("SYSTEM\\CurrentControlSet\\Control\\WMI\\Autologger\\EIDCredentialProvider"), 
		TEXT("LogFileMode"), REG_DWORD,&dwValue,sizeof(DWORD));
	if (err != ERROR_SUCCESS) {MessageBoxWin32(err); return;}
	dwValue = 5;
	err = RegSetKeyValue(	HKEY_LOCAL_MACHINE, 
		TEXT("SYSTEM\\CurrentControlSet\\Control\\WMI\\Autologger\\EIDCredentialProvider"), 
		TEXT("FileCounter"), REG_DWORD,&dwValue,sizeof(DWORD));
	if (err != ERROR_SUCCESS) {MessageBoxWin32(err); return;}
	dwValue = 0;
	err = RegSetKeyValue(	HKEY_LOCAL_MACHINE, 
		TEXT("SYSTEM\\CurrentControlSet\\Control\\WMI\\Autologger\\EIDCredentialProvider"), 
		TEXT("Status"), REG_DWORD,&dwValue,sizeof(DWORD));
	if (err != ERROR_SUCCESS) {MessageBoxWin32(err); return;}

	dwValue = 1;
	err = RegSetKeyValue(	HKEY_LOCAL_MACHINE, 
		TEXT("SYSTEM\\CurrentControlSet\\Control\\WMI\\Autologger\\EIDCredentialProvider\\{B4866A0A-DB08-4835-A26F-414B46F3244C}"), 
		TEXT("Enabled"), REG_DWORD,&dwValue,sizeof(DWORD));
	if (err != ERROR_SUCCESS) {MessageBoxWin32(err); return;}
	dwValue = 5;
	err = RegSetKeyValue(	HKEY_LOCAL_MACHINE, 
		TEXT("SYSTEM\\CurrentControlSet\\Control\\WMI\\Autologger\\EIDCredentialProvider\\{B4866A0A-DB08-4835-A26F-414B46F3244C}"), 
		TEXT("EnableLevel"), REG_DWORD,&dwValue,sizeof(DWORD));
	if (err != ERROR_SUCCESS) {MessageBoxWin32(err); return;}
	dwValue = 0;
	err = RegSetKeyValue(	HKEY_LOCAL_MACHINE, 
		TEXT("SYSTEM\\CurrentControlSet\\Control\\WMI\\Autologger\\EIDCredentialProvider\\{B4866A0A-DB08-4835-A26F-414B46F3244C}"), 
		TEXT("EnableProperty"), REG_DWORD,&dwValue,sizeof(DWORD));
	if (err != ERROR_SUCCESS) {MessageBoxWin32(err); return;}
	dwValue = 0;
	err = RegSetKeyValue(	HKEY_LOCAL_MACHINE, 
		TEXT("SYSTEM\\CurrentControlSet\\Control\\WMI\\Autologger\\EIDCredentialProvider\\{B4866A0A-DB08-4835-A26F-414B46F3244C}"), 
		TEXT("Status"), REG_DWORD,&dwValue,sizeof(DWORD));
	if (err != ERROR_SUCCESS) {MessageBoxWin32(err); return;}
	qdwValue = 0;
	err = RegSetKeyValue(	HKEY_LOCAL_MACHINE, 
		TEXT("SYSTEM\\CurrentControlSet\\Control\\WMI\\Autologger\\EIDCredentialProvider\\{B4866A0A-DB08-4835-A26F-414B46F3244C}"), 
		TEXT("MatchAllKeyword"), REG_QWORD,&qdwValue,sizeof(DWORD64));
	if (err != ERROR_SUCCESS) {MessageBoxWin32(err); return;}
	qdwValue = 0;
	err = RegSetKeyValue(	HKEY_LOCAL_MACHINE, 
		TEXT("SYSTEM\\CurrentControlSet\\Control\\WMI\\Autologger\\EIDCredentialProvider\\{B4866A0A-DB08-4835-A26F-414B46F3244C}"), 
		TEXT("MatchAnyKeyword"), REG_QWORD,&qdwValue,sizeof(DWORD64));
	if (err != ERROR_SUCCESS) {MessageBoxWin32(err); return;}
	StartLogging();
}

void DisableLogging()
{
	
	BOOL fSuccess = RegDelnode(HKEY_LOCAL_MACHINE, TEXT("SYSTEM\\CurrentControlSet\\Control\\WMI\\Autologger\\EIDCredentialProvider"));
	if (!fSuccess) {MessageBoxWin32(GetLastError()); return;}
	StopLogging();
}

BOOL IsLoggingEnabled()
{
	HKEY hkResult;
	DWORD Status;
	BOOL fReturn = FALSE;
	Status=RegOpenKeyEx(HKEY_LOCAL_MACHINE,TEXT("SYSTEM\\CurrentControlSet\\Control\\WMI\\Autologger\\EIDCredentialProvider"),0,KEY_READ|KEY_QUERY_VALUE|KEY_WRITE,&hkResult);
	if (Status == ERROR_SUCCESS) {
		fReturn = TRUE;
		RegCloseKey(hkResult);
	}
	return fReturn;
}

BOOL Is64BitOS()
{
   BOOL bIs64BitOS = FALSE;

   // We check if the OS is 64 Bit
   typedef BOOL (WINAPI *LPFN_ISWOW64PROCESS) (HANDLE, PBOOL); 

   LPFN_ISWOW64PROCESS
      fnIsWow64Process = (LPFN_ISWOW64PROCESS)GetProcAddress(GetModuleHandle(TEXT("kernel32")),"IsWow64Process");
 
   if (NULL != fnIsWow64Process)
   {
      if (!fnIsWow64Process(GetCurrentProcess(),&bIs64BitOS))
      {
         //error
      }
   }
   return bIs64BitOS;
}

void EnableCrashDump(PTSTR szPath)
{
	DWORD dwDumpType = 2;
	DWORD dwFlag = 0;
#if defined _M_IX86
	if (Is64BitOS())
	{
		dwFlag = KEY_WOW64_64KEY;
	}
#endif
	DWORD Status;
	HKEY hkResult = 0;
	__try
	{
		Status=RegCreateKeyEx(HKEY_LOCAL_MACHINE,TEXT("SOFTWARE\\Microsoft\\Windows\\Windows Error Reporting\\LocalDumps\\lsass.exe"),
			0,NULL,0,KEY_READ|KEY_QUERY_VALUE|KEY_WRITE|dwFlag,NULL,&hkResult,NULL);
		if (Status != ERROR_SUCCESS) {MessageBoxWin32(Status); __leave;}
		Status = RegSetValueEx(hkResult,TEXT("DumpFolder"),0,REG_SZ, (PBYTE) szPath,((DWORD)sizeof(TCHAR))*((DWORD)_tcslen(szPath)+1));
		if (Status != ERROR_SUCCESS) {MessageBoxWin32(Status); __leave;}
		Status = RegSetValueEx(hkResult,TEXT("DumpType"),0, REG_DWORD, (PBYTE)&dwDumpType,sizeof(dwDumpType));
		if (Status != ERROR_SUCCESS) {MessageBoxWin32(Status); __leave;}
	}
	__finally
	{
		if (hkResult)
			RegCloseKey(hkResult);
	}
}

void DisableCrashDump()
{
	HKEY hkResult;
	DWORD Status;
	DWORD dwFlag = 0;
#if defined _M_IX86
	if (Is64BitOS())
	{
		dwFlag = KEY_WOW64_64KEY;
	}
#endif
	Status=RegOpenKeyEx(HKEY_LOCAL_MACHINE,TEXT("SOFTWARE\\Microsoft\\Windows\\Windows Error Reporting\\LocalDumps"),0,KEY_READ|KEY_QUERY_VALUE|KEY_WRITE|dwFlag,&hkResult);
	if (Status == ERROR_SUCCESS) {
		RegDeleteKey(hkResult, TEXT("lsass.exe"));
		RegCloseKey(hkResult);
	}
}

BOOL IsCrashDumpEnabled()
{
	HKEY hkResult;
	DWORD Status;
	DWORD dwFlag = 0;
	BOOL fReturn = FALSE;
#if defined _M_IX86
	if (Is64BitOS())
	{
		dwFlag = KEY_WOW64_64KEY;
	}
#endif
	Status=RegOpenKeyEx(HKEY_LOCAL_MACHINE,TEXT("SOFTWARE\\Microsoft\\Windows\\Windows Error Reporting\\LocalDumps\\lsass.exe"),0,KEY_READ|KEY_QUERY_VALUE|KEY_WRITE|dwFlag,&hkResult);
	if (Status == ERROR_SUCCESS) {
		fReturn = TRUE;
		RegCloseKey(hkResult);
	}
	return fReturn;
}