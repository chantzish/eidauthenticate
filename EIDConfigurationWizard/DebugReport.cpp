#include <windows.h>
#include <tchar.h>
#include <wincred.h>
#include <ntsecapi.h>
#include <wmistr.h>
#include <Evntrace.h>

#include "global.h"
#include "EIDConfigurationWizard.h"

#include "../EIDCardLibrary/EIDCardLibrary.h"
#include "../EIDCardLibrary/Package.h"
#include "../EIDCardLibrary/Tracing.h"
#include "../EIDCardLibrary/OnlineDatabase.h"

#pragma comment(lib,"Credui")

BOOL TestLogon(HWND hMainWnd)
{
	BOOL save = false;
	DWORD authPackage = 0;
	LPVOID authBuffer;
	ULONG authBufferSize = 0;
	CREDUI_INFO credUiInfo;
	BOOL fReturn = FALSE;
	DWORD dwError = 0;

	LSA_HANDLE hLsa;
	LSA_STRING Origin = { (USHORT)strlen("MYTEST"), (USHORT)sizeof("MYTEST"), "MYTEST" };
	QUOTA_LIMITS Quota = {0};
	TOKEN_SOURCE Source = { "TEST", { 0, 101 } };
	MSV1_0_INTERACTIVE_PROFILE *Profile;
	ULONG ProfileLen;
	LUID Luid;
	NTSTATUS err,stat;
	HANDLE Token;
	DWORD dwFlag = CREDUIWIN_AUTHPACKAGE_ONLY | CREDUIWIN_ENUMERATE_CURRENT_USER;
	RetrieveNegotiateAuthPackage(&authPackage);
	
	CoInitializeEx(NULL,COINIT_APARTMENTTHREADED); 
	TCHAR szTitle[256] = TEXT("");
	TCHAR szMessage[256] = TEXT("");
	TCHAR szCaption[256] = TEXT("");
	LoadString(g_hinst, IDS_05CREDINFOCAPTION, szCaption, ARRAYSIZE(szCaption));
	//LoadString(g_hinst, IDS_05CREDINFOMESSAGE, szMessage, ARRAYSIZE(szMessage));
	credUiInfo.pszCaptionText = szCaption;
	credUiInfo.pszMessageText = szMessage;
	credUiInfo.cbSize = sizeof(credUiInfo);
	credUiInfo.hbmBanner = NULL;
	credUiInfo.hwndParent = hMainWnd;

	DWORD result = CredUIPromptForWindowsCredentials(&(credUiInfo), 0, &(authPackage), 
					NULL, 0, &authBuffer, &authBufferSize, &(save), dwFlag);
	if (result == ERROR_SUCCESS)
	{
		err = LsaConnectUntrusted(&hLsa);
		/* Find the setuid package and call it */
		err = LsaLogonUser(hLsa, &Origin, (SECURITY_LOGON_TYPE)  Interactive , authPackage, authBuffer,authBufferSize,NULL, &Source, (PVOID*)&Profile, &ProfileLen, &Luid, &Token, &Quota, &stat);
		DWORD dwSize = sizeof(MSV1_0_INTERACTIVE_PROFILE);
		LsaDeregisterLogonProcess(hLsa);
		if (err)
		{
			dwError = LsaNtStatusToWinError(err);
		}
		else
		{
			/*LoadString(g_hinst, IDS_05CREDINFOCONFIRMTITLE, szTitle, ARRAYSIZE(szTitle));
			LoadString(g_hinst, IDS_05CREDINFOCONFIRMMESSAGE, szMessage, ARRAYSIZE(szMessage));
			MessageBox(hMainWnd,szMessage,szTitle,0);*/
			fReturn = TRUE;
			
			LsaFreeReturnBuffer(Profile);
			CloseHandle(Token);
			
		}
		CoTaskMemFree(authBuffer);
	}
	else //if (result == ERROR_CANCELLED)
	{
		//fReturn = TRUE;
		dwError = result;
	}
	//else
	//{
	//	//MessageBoxWin32(GetLastError());
	//}
	//CredUIConfirmCredentials(NULL,FALSE);
	SetLastError(dwError);
	return fReturn;
}

HANDLE hFile = NULL;

VOID WINAPI ProcessEvents(PEVENT_TRACE pEvent)
{
  // Is this the first event of the session? The event is available only if
  // you are consuming events from a log file, not a real-time session.
  {
    //Process the event. The pEvent->MofData member is a pointer to 
    //the event specific data, if it exists.
	  if (pEvent->MofLength)
	  {
		DWORD dwWritten;
		FILETIME ft;
		SYSTEMTIME st;
		ft.dwHighDateTime = pEvent->Header.TimeStamp.HighPart;
		ft.dwLowDateTime = pEvent->Header.TimeStamp.LowPart;
		FileTimeToSystemTime(&ft,&st);
		TCHAR szLocalDate[255], szLocalTime[255];
		_stprintf_s(szLocalDate, ARRAYSIZE(szLocalDate),TEXT("%04d-%02d-%02d"),st.wYear,st.wMonth,st.wDay);
		_stprintf_s(szLocalTime, ARRAYSIZE(szLocalTime),TEXT("%02d:%02d:%02d"),st.wHour,st.wMinute,st.wSecond);
		WriteFile ( hFile, szLocalDate, (DWORD)_tcslen(szLocalDate) * (DWORD)sizeof(TCHAR), &dwWritten, NULL);
		WriteFile ( hFile, TEXT(";"), 1 * (DWORD)sizeof(TCHAR), &dwWritten, NULL);
		WriteFile ( hFile, szLocalTime, (DWORD)_tcslen(szLocalTime) * (DWORD)sizeof(TCHAR), &dwWritten, NULL);
		WriteFile ( hFile, TEXT(";"), 1 * (DWORD)sizeof(TCHAR), &dwWritten, NULL);
		WriteFile ( hFile, pEvent->MofData, (DWORD)_tcslen((PTSTR) pEvent->MofData) * (DWORD)sizeof(TCHAR), &dwWritten, NULL);
		WriteFile ( hFile, TEXT("\r\n"), 2 * (DWORD)sizeof(TCHAR), &dwWritten, NULL);
	  }
  }

  return;
}

void ExportOneTraceFile(PTSTR szTraceFile)
{
	ULONG rc;
	TRACEHANDLE handle = NULL;
	EVENT_TRACE_LOGFILE trace;
	memset(&trace,0, sizeof(EVENT_TRACE_LOGFILE));
	trace.LoggerName = TEXT("EIDCredentialProvider"); 
	//trace.LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
	trace.LogFileName = szTraceFile;
	trace.EventCallback = (PEVENT_CALLBACK) (ProcessEvents);
	handle = OpenTrace(&trace);
	if ((TRACEHANDLE)INVALID_HANDLE_VALUE == handle)
	{
		// Handle error as appropriate for your application.
	}
	else
	{
		FILETIME now, start;
		SYSTEMTIME sysNow, sysstart;
		GetLocalTime(&sysNow);
		SystemTimeToFileTime(&sysNow, &now);
		memcpy(&sysstart, &sysNow, sizeof(SYSTEMTIME));
		sysstart.wYear -= 1;
		SystemTimeToFileTime(&sysstart, &start);
		DWORD dwWritten;
		TCHAR szBuffer[256];
		_tcscpy_s(szBuffer,ARRAYSIZE(szBuffer),TEXT("================================================\r\n"));
		WriteFile ( hFile, szBuffer, (DWORD)_tcslen(szBuffer) * (DWORD)sizeof(TCHAR), &dwWritten, NULL);
		WriteFile ( hFile, szTraceFile, (DWORD)_tcslen(szTraceFile) * (DWORD)sizeof(TCHAR), &dwWritten, NULL);
		_tcscpy_s(szBuffer,ARRAYSIZE(szBuffer),TEXT("\r\n"));
		WriteFile ( hFile, szBuffer, (DWORD)_tcslen(szBuffer) * (DWORD)sizeof(TCHAR), &dwWritten, NULL);
		_tcscpy_s(szBuffer,ARRAYSIZE(szBuffer),TEXT("================================================\r\n"));
		WriteFile ( hFile, szBuffer, (DWORD)_tcslen(szBuffer) * (DWORD)sizeof(TCHAR), &dwWritten, NULL);
		rc = ProcessTrace(&handle, 1, 0, 0);
		if (rc != ERROR_SUCCESS && rc != ERROR_CANCELLED)
		{
			if (rc ==  0x00001069)
			{
			}
			else
			{
			}
		}
		CloseTrace(handle);
	}
}

BOOL CreateDebugReportElevated(PTSTR szLogFile)
{
	DWORD dwError;
	BOOL fSuccess = FALSE;
	HANDLE hOutput = INVALID_HANDLE_VALUE;
	__try
	{
		//  Creates the new file to write to for the upper-case version.
		hOutput = CreateFile((LPTSTR) szLogFile, // file name 
							   GENERIC_WRITE,        // open for write 
							   0,                    // do not share 
							   NULL,                 // default security 
							   CREATE_ALWAYS,        // overwrite existing
							   FILE_ATTRIBUTE_NORMAL,// normal file 
							   NULL);                // no template 
		if (hOutput == INVALID_HANDLE_VALUE) 
		{ 
			__leave;
		}
		// hFile MUST be a module variable because the callback can't use any parameter
		hFile = hOutput;
		// disable the logging, just in case if was active
		StopLogging();
		// enable the logging
		if (!StartLogging())
		{
			__leave;
		}
		// call for a test
		if (!TestLogon(NULL))
		{
			dwError = GetLastError();
			if (dwError == ERROR_CANCELLED)
			{
				__leave;
			}
		}
		// disable the logging
		StopLogging();
		// get the text
		ExportOneTraceFile(TEXT("c:\\Windows\\system32\\LogFiles\\WMI\\EIDCredentialProvider.etl"));
		fSuccess = TRUE;
	}
	__finally
	{
		if (hOutput != INVALID_HANDLE_VALUE)
		{
			CloseHandle(hOutput);
		}
	}
	return fSuccess;
}

BOOL CreateDebugReport(PTSTR szLogFile)
{
	BOOL fReturn = FALSE;
	DWORD dwError = 0;
	
	if (IsElevated())
	{	
		
		fReturn = CreateDebugReportElevated(szLogFile);
	}
	else
	{
		// elevate
		SHELLEXECUTEINFO shExecInfo;
		TCHAR szParameters[MAX_PATH + 100] = TEXT("DEBUGREPORT ");
		TCHAR szName[1024];
		GetModuleFileName(GetModuleHandle(NULL),szName, ARRAYSIZE(szName));
		_tcscat_s(szParameters, ARRAYSIZE(szParameters),szLogFile);

		shExecInfo.cbSize = sizeof(SHELLEXECUTEINFO);
		shExecInfo.fMask = SEE_MASK_NOCLOSEPROCESS;
		shExecInfo.hwnd = NULL;
		shExecInfo.lpVerb = TEXT("runas");
		shExecInfo.lpFile = szName;
		shExecInfo.lpParameters = szParameters;
		shExecInfo.lpDirectory = NULL;
		shExecInfo.nShow = SW_NORMAL;
		shExecInfo.hInstApp = NULL;

		if (!ShellExecuteEx(&shExecInfo))
		{
			dwError = GetLastError();
		}
		else
		{
			if (WaitForSingleObject(shExecInfo.hProcess, INFINITE) == WAIT_OBJECT_0)
			{
				fReturn = TRUE;
			}
			else
			{
				dwError = GetLastError();
			}
		}
	}
	SetLastError(dwError);
	return fReturn;
}

BOOL SendReport(DWORD dwErrorCode, PTSTR szEmail)
{
	DWORD dwRetVal;
	UINT uRetVal;
	TCHAR lpTempPathBuffer[MAX_PATH];
	TCHAR szTempFileName[MAX_PATH] = TEXT("");
	
	BOOL fReturn = FALSE;
	__try
	{
		// create a unique temp file
		// we need to use a temp file to communicate between the elevated process and this one
		// we can also use a pipe.
		dwRetVal = GetTempPath(MAX_PATH, lpTempPathBuffer);
		if (dwRetVal > MAX_PATH || (dwRetVal == 0))
		{
			__leave;
		}
		uRetVal = GetTempFileName(lpTempPathBuffer, TEXT("EIDAUTHENTICATE"), 0, szTempFileName);
		if (uRetVal == 0)
		{
			__leave;
		}
		if (!CreateDebugReport(szTempFileName))
		{
			__leave;
		}
		if (!CommunicateTestNotOK(dwErrorCode, szEmail, szTempFileName))
		{
			__leave;
		}
		fReturn = TRUE;
	}
	__finally
	{
		if (_tcslen(szTempFileName) > 0)
		{
			DeleteFile(szTempFileName);
		}
	}
	return fReturn;
}