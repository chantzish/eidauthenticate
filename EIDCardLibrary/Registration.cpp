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
#include <Wmistr.h>
#include <Evntrace.h>

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

/** Installation and uninstallation routine
*/

void EIDAuthenticationPackageDllRegister()
{
	AppendValueToMultiSz(HKEY_LOCAL_MACHINE, TEXT("SYSTEM\\CurrentControlSet\\Control\\Lsa"), TEXT("Security Packages"), AUTHENTICATIONPACKAGENAMET);
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
	RegDeleteTree(HKEY_CLASSES_ROOT, TEXT("CLSID\\{B4866A0A-DB08-4835-A26F-414B46F3244C}"));
	RegDeleteTree(HKEY_LOCAL_MACHINE, 
		TEXT("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Authentication\\Credential Providers\\{B4866A0A-DB08-4835-A26F-414B46F3244C}"));
	RegDeleteTree(HKEY_LOCAL_MACHINE, 
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


}

void EIDConfigurationWizardDllUnRegister()
{
	RegDeleteTree(HKEY_LOCAL_MACHINE, TEXT("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ControlPanel\\NameSpace\\{F5D846B4-14B0-11DE-B23C-27A355D89593}"));
	RegDeleteTree(HKEY_CLASSES_ROOT, TEXT("CLSID\\{F5D846B4-14B0-11DE-B23C-27A355D89593}"));
}

BOOL StartLogging()
{
	BOOL fReturn = FALSE;
	TRACEHANDLE SessionHandle;
	struct _Prop
	{
		EVENT_TRACE_PROPERTIES TraceProperties;
		TCHAR LogFileName[1024];
		TCHAR LoggerName[1024];
	} Properties;
	ULONG err;
	__try
	{
		memset(&Properties, 0, sizeof(Properties));
		Properties.TraceProperties.Wnode.BufferSize = sizeof(Properties);
		Properties.TraceProperties.Wnode.Guid = CLSID_CEIDProvider;
		Properties.TraceProperties.Wnode.Flags = WNODE_FLAG_TRACED_GUID;
		Properties.TraceProperties.Wnode.ClientContext = 1;
		Properties.TraceProperties.LogFileMode = 4864; 
		Properties.TraceProperties.LogFileNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
		Properties.TraceProperties.LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES) + 1024;
		Properties.TraceProperties.MaximumFileSize = 8;
		_tcscpy_s(Properties.LogFileName,1024,TEXT("c:\\Windows\\system32\\LogFiles\\WMI\\EIDCredentialProvider.etl"));
		//_tcscpy_s(Properties.LoggerName,1024,TEXT("EIDCredentialProvider"));
		DeleteFile(Properties.LogFileName);
		err = StartTrace(&SessionHandle, TEXT("EIDCredentialProvider"), &(Properties.TraceProperties));
		if (err != ERROR_SUCCESS)
		{
			MessageBoxWin32(err);
			__leave;
		}
		err = EnableTraceEx(&CLSID_CEIDProvider,NULL,SessionHandle,TRUE,WINEVENT_LEVEL_VERBOSE,0,0,0,NULL);
		if (err != ERROR_SUCCESS)
		{
			MessageBoxWin32(err);
			__leave;
		}
		fReturn = TRUE;
	}
	__finally
	{
	}
	return fReturn;
}

void StopLogging()
{
	LONG err;
	struct _Prop
	{
		EVENT_TRACE_PROPERTIES TraceProperties;
		TCHAR LogFileName[1024];
		TCHAR LoggerName[1024];
	} Properties;
	memset(&Properties, 0, sizeof(Properties));
	Properties.TraceProperties.Wnode.BufferSize = sizeof(Properties);
	Properties.TraceProperties.Wnode.Guid = CLSID_CEIDProvider;
	Properties.TraceProperties.Wnode.Flags = WNODE_FLAG_TRACED_GUID;
	Properties.TraceProperties.LogFileMode = 4864; 
	Properties.TraceProperties.LogFileNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
	Properties.TraceProperties.LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES) + 1024 * sizeof(TCHAR);
	Properties.TraceProperties.MaximumFileSize = 8;
	err = ControlTrace(NULL, TEXT("EIDCredentialProvider"), &(Properties.TraceProperties),EVENT_TRACE_CONTROL_STOP);
	if (err != ERROR_SUCCESS && err != 0x00001069)
	{
		MessageBoxWin32(err);
	}
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
	
	LONG err = RegDeleteTree(HKEY_LOCAL_MACHINE, TEXT("SYSTEM\\CurrentControlSet\\Control\\WMI\\Autologger\\EIDCredentialProvider"));
	if (err != ERROR_SUCCESS) {MessageBoxWin32(err); return;}
	StopLogging();
}

void BEID_Patch()
{
	BYTE bATR[]		= {0x3b,0x98,0x13,0x40,0x0a,0xa5,0x03,0x01,0x01,0x01,0xad,0x13,0x11};
	BYTE bATRMASK[] = {0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff};
	RegSetKeyValue(	HKEY_LOCAL_MACHINE, 
		TEXT("SOFTWARE\\Microsoft\\Cryptography\\Calais\\SmartCards\\Belgium Electronic ID card"), 
		TEXT("Crypto Provider"), REG_SZ,TEXT("Belgium Identity Card CSP"),sizeof(TEXT("Belgium Identity Card CSP")));
	RegSetKeyValue(	HKEY_LOCAL_MACHINE, 
		TEXT("SOFTWARE\\Microsoft\\Cryptography\\Calais\\SmartCards\\Belgium Electronic ID card"), 
		TEXT("ATR"), REG_BINARY,bATR,sizeof(bATR));
	RegSetKeyValue(	HKEY_LOCAL_MACHINE, 
		TEXT("SOFTWARE\\Microsoft\\Cryptography\\Calais\\SmartCards\\Belgium Electronic ID card"), 
		TEXT("ATRMask"), REG_BINARY,bATRMASK,sizeof(bATRMASK));
#ifdef  _M_X64
	RegSetKeyValue(	HKEY_LOCAL_MACHINE, 
		TEXT("SOFTWARE\\Wow6432Node\\Microsoft\\Cryptography\\Calais\\SmartCards\\Belgium Electronic ID card"), 
		TEXT("Crypto Provider"), REG_SZ,TEXT("Belgium Identity Card CSP"),sizeof(TEXT("Belgium Identity Card CSP")));
	RegSetKeyValue(	HKEY_LOCAL_MACHINE, 
		TEXT("SOFTWARE\\Wow6432Node\\Microsoft\\Cryptography\\Calais\\SmartCards\\Belgium Electronic ID card"), 
		TEXT("ATR"), REG_BINARY,bATR,sizeof(bATR));
	RegSetKeyValue(	HKEY_LOCAL_MACHINE, 
		TEXT("SOFTWARE\\Wow6432Node\\Microsoft\\Cryptography\\Calais\\SmartCards\\Belgium Electronic ID card"), 
		TEXT("ATRMask"), REG_BINARY,bATRMASK,sizeof(bATRMASK));
#endif
}

void BEID_UnPatch()
{
	RegDeleteTree(HKEY_LOCAL_MACHINE, TEXT("SOFTWARE\\Microsoft\\Cryptography\\Calais\\SmartCards\\Belgium Electronic ID card"));
}