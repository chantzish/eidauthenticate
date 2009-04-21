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
#include <stdio.h>
#include <Evntprov.h>
#include <crtdbg.h>

#define _CRTDBG_MAPALLOC

#include "guid.h"

#define WINEVENT_LEVEL_CRITICAL 1
#define WINEVENT_LEVEL_ERROR    2
#define WINEVENT_LEVEL_WARNING  3
#define WINEVENT_LEVEL_INFO     4
#define WINEVENT_LEVEL_VERBOSE  5

REGHANDLE hPub;
BOOL bFirst = TRUE;
WCHAR Section[100];

/**
 *  Tracing function.
 *  Extract data using :
 * C:\Windows\System32\LogFiles\WMI>tracerpt EIDCredentialProvider.etl.001 -o c:\us
 * ers\Adiant\Desktop\report.txt -of csv
 */

/**
 *  Display a messagebox giving an error code
 */
void MessageBoxWin32Ex(DWORD status, LPCSTR szFile, DWORD dwLine) {
	LPVOID Error;
	TCHAR szTitle[1024];
#ifdef UNICODE
	_stprintf_s(szTitle,ARRAYSIZE(szTitle),TEXT("%S(%d)"),szFile, dwLine);
#else
	_stprintf_s(szTitle,ARRAYSIZE(szTitle),TEXT("%s(%d)"),szFile, dwLine);
#endif
	FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER|FORMAT_MESSAGE_FROM_SYSTEM,
		NULL,status,0,(LPTSTR)&Error,0,NULL);
	MessageBox(NULL,(LPCTSTR)Error,szTitle ,MB_ICONASTERISK);
	LocalFree(Error);
}

void EIDCardLibraryTracingRegister() {
	bFirst = FALSE;
	EventRegister(&CLSID_CEIDProvider,NULL,NULL,&hPub);
}

void EIDCardLibraryTracingUnRegister() {
	EventUnregister(hPub);
}


void EIDCardLibraryTraceEx(LPCSTR szFile, DWORD dwLine, LPCSTR szFunction, UCHAR dwLevel, PCWSTR szFormat,...) {
	_ASSERTE( _CrtCheckMemory( ) );
#ifndef _DEBUG
	UNREFERENCED_PARAMETER(dwLine);
	UNREFERENCED_PARAMETER(szFile);
#endif
	WCHAR Buffer[256];
	WCHAR Buffer2[356];
	int ret;
	va_list ap;

	if (bFirst) EIDCardLibraryTracingRegister();

	va_start (ap, szFormat);
	ret = _vsnwprintf_s (Buffer, 256, 256, szFormat, ap);
	va_end (ap);
	if (ret <= 0) return;
	if (ret > 256) ret = 255;
	Buffer[255] = L'\0';/*
	if ((ret>2) && (ret< 254) && (Buffer[ret-1] != L'\n') && (Buffer[ret-2] != L'\n')) {
		wcscat_s(Buffer,256,L"\r\n");
		ret+=2;
	}*/
#ifdef _DEBUG
	swprintf_s(Buffer2,356,L"%S(%d) : %S - %s\r\n",szFile,dwLine,szFunction,Buffer);
	OutputDebugString(Buffer2);
#endif
	swprintf_s(Buffer2,356,L"%S(%d) : %s",szFunction,dwLine,Buffer);
	EventWriteString(hPub,dwLevel,0,Buffer2);

}


void EIDCardLibraryDumpMemoryEx(LPCSTR szFile, DWORD dwLine, LPCSTR szFunction, PUCHAR memory, DWORD memorysize)
{
	DWORD i,j;
	UCHAR buffer[10];
	PWSTR szFormat = L"%3d %3d %3d %3d %3d %3d %3d %3d %3d %3d";
	for (i = 0; i < memorysize; i++)
	{
		buffer[i%10] = memory[i];
		if (i%10 == 9) 
		{
			EIDCardLibraryTraceEx(szFile,dwLine,szFunction, WINEVENT_LEVEL_VERBOSE, szFormat,
				buffer[0],buffer[1],buffer[2],buffer[3],buffer[4],
				buffer[5],buffer[6],buffer[7],buffer[8],buffer[9]);
		}
		if ((i == memorysize-1) && (i%10 != 9))
		{
			// last bytes
			for (j = 0; j <10; j++)
			{
				buffer[j]=255;
			}
			for (j = memorysize - memorysize%10; j <memorysize; j++) 
			{
				buffer[j%10] = memory[j];
			}
			szFormat[(memorysize%10) * 4] = 0;
			EIDCardLibraryTraceEx(szFile,dwLine,szFunction, WINEVENT_LEVEL_VERBOSE, szFormat,
				buffer[0],buffer[1],buffer[2],buffer[3],buffer[4],
				buffer[5],buffer[6],buffer[7],buffer[8],buffer[9]);
		}
	}

}