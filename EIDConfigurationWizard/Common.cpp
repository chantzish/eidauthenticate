#include <windows.h>
#include <tchar.h>
#include <Lm.h>

#include "../EIDCardLibrary/GPO.h"
#include "../EIDCardLibrary/Tracing.h"
#include "EIDConfigurationWizard.h"

extern HINSTANCE g_hinst;

VOID CenterWindow(HWND hWnd)
{
  HWND hWndParent;
  RECT rcParent;
  RECT rcWindow;

  hWndParent = GetParent(hWnd);
  if (hWndParent == NULL)
    hWndParent = GetDesktopWindow();

  GetWindowRect(hWndParent, &rcParent);
  GetWindowRect(hWnd, &rcWindow);

  SetWindowPos(hWnd,
	       HWND_TOP,
	       ((rcParent.right - rcParent.left) - (rcWindow.right - rcWindow.left)) / 2,
	       ((rcParent.bottom - rcParent.top) - (rcWindow.bottom - rcWindow.top)) / 2,
	       0,
	       0,
	       SWP_NOSIZE);
}


BOOL IsElevated()
{
	BOOL fReturn = FALSE;
	HANDLE hToken	= NULL;

	if ( !OpenProcessToken( GetCurrentProcess(), TOKEN_QUERY, &hToken ) )
	{
		return FALSE;
	}

	TOKEN_ELEVATION te = { 0 };
	DWORD dwReturnLength = 0;

	if ( GetTokenInformation(
				hToken,
				TokenElevation,
				&te,
				sizeof( te ),
				&dwReturnLength ) )
	{
	
		fReturn = te.TokenIsElevated ? TRUE : FALSE; 
	}

	CloseHandle(hToken);

	return fReturn;
}

#if WINVER < 0x600
// this function doesn't exists on xp, only since Vista.
// already implemented in EIDCardLibrary
// let the linker grab it
LONG WINAPI RegSetKeyValueXP(
  __in      HKEY hKey,
  __in_opt  LPCTSTR lpSubKey,
  __in_opt  LPCTSTR lpValueName,
  __in      DWORD dwType,
  __in_opt  LPCVOID lpData,
  __in      DWORD cbData
);
#define RegSetKeyValue RegSetKeyValueXP
#endif

BOOL ChangeRemovePolicyElevated(DWORD dwActivate)
{
	TCHAR szValue[2];
	LONG lReturn;
	DWORD dwError = 0;
	SC_HANDLE hService = NULL;
	SC_HANDLE hServiceManager = NULL;
	SERVICE_STATUS ServiceStatus;
	
	_stprintf_s(szValue, ARRAYSIZE(szValue), TEXT("%d"),dwActivate);
	__try
	{
		lReturn = RegSetKeyValue(HKEY_LOCAL_MACHINE, 
			TEXT("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon"),
			TEXT("scremoveoption"), REG_SZ, szValue,sizeof(TCHAR)*ARRAYSIZE(szValue));
		if ( lReturn != ERROR_SUCCESS)
		{
			dwError = lReturn;
			__leave;
		}
		hServiceManager = OpenSCManager(NULL,NULL,SC_MANAGER_CONNECT);
		if (!hServiceManager)
		{
			dwError = GetLastError();
			__leave;
		}
		hService = OpenService(hServiceManager, TEXT("ScPolicySvc"), SERVICE_CHANGE_CONFIG | SERVICE_START | SERVICE_STOP | SERVICE_QUERY_STATUS);
		if (!hService)
		{
			dwError = GetLastError();
			__leave;
		}
		if (dwActivate)
		{	
			// start service
			if (!ChangeServiceConfig(hService, SERVICE_NO_CHANGE, SERVICE_AUTO_START, SERVICE_NO_CHANGE, NULL, NULL, NULL, NULL, NULL, NULL, NULL))
			{
				dwError = GetLastError();
				__leave;
			}
			if (!StartService(hService,0,NULL))
			{
				dwError = GetLastError();
				__leave;
			}
		}
		else
		{ 
			// stop service
			if (!ChangeServiceConfig(hService, SERVICE_NO_CHANGE, SERVICE_DEMAND_START, SERVICE_NO_CHANGE, NULL, NULL, NULL, NULL, NULL, NULL, NULL))
			{
				dwError = GetLastError();
				__leave;
			}
			if (!ControlService(hService,SERVICE_CONTROL_STOP,&ServiceStatus))
			{
				dwError = GetLastError();
				if (dwError == ERROR_SERVICE_NOT_ACTIVE)
				{
					// service not active is not an error
					dwError = 0;
				}
				__leave;
			}
			//Boucle d'attente de l'arret
			do{
				if (!QueryServiceStatus(hService,&ServiceStatus))
				{
					dwError = GetLastError();
					__leave;
				}
				Sleep(100);
			} while(ServiceStatus.dwCurrentState != SERVICE_STOPPED); 
		}
	}
	__finally
	{
		if (hService)
			CloseServiceHandle(hService);
		if (hServiceManager)
			CloseServiceHandle(hServiceManager);
	}
	return dwError == 0;
}

BOOL ChangeRemovePolicy(BOOL fActivate)
{
	BOOL fReturn = FALSE;
	DWORD dwError = 0;
	if (IsElevated())
	{	
		return ChangeRemovePolicyElevated(fActivate);
	}
	else
	{
		// elevate
		SHELLEXECUTEINFO shExecInfo;
		TCHAR szName[1024];
		GetModuleFileName(GetModuleHandle(NULL),szName, ARRAYSIZE(szName));
		shExecInfo.cbSize = sizeof(SHELLEXECUTEINFO);

		shExecInfo.fMask = SEE_MASK_NOCLOSEPROCESS;
		shExecInfo.hwnd = NULL;
		shExecInfo.lpVerb = TEXT("runas");
		shExecInfo.lpFile = szName;
		if (fActivate)
		{
			shExecInfo.lpParameters = TEXT("ACTIVATEREMOVEPOLICY");
		}
		else
		{
			shExecInfo.lpParameters = TEXT("DESACTIVATEREMOVEPOLICY");
		}
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

BOOL ChangeForceSmartCardLogonPolicy(BOOL fActivate)
{
	DWORD dwValue;
	BOOL fReturn = FALSE;
	DWORD dwError = 0;
	if (IsElevated())
	{
		if (fActivate)
		{
			dwValue = 1;
		}
		else
		{
			dwValue = 0;
		}
		return RegSetKeyValue(	HKEY_LOCAL_MACHINE, 
			TEXT("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Policies\\System"),
			TEXT("scforceoption"), REG_DWORD, &dwValue,sizeof(dwValue)) == ERROR_SUCCESS;
	}
	else
	{
	// elevate
		SHELLEXECUTEINFO shExecInfo;
		TCHAR szName[1024];
		GetModuleFileName(GetModuleHandle(NULL),szName, ARRAYSIZE(szName));
		shExecInfo.cbSize = sizeof(SHELLEXECUTEINFO);

		shExecInfo.fMask = SEE_MASK_NOCLOSEPROCESS;
		shExecInfo.hwnd = NULL;
		shExecInfo.lpVerb = TEXT("runas");
		shExecInfo.lpFile = szName;
		if (fActivate)
		{
			shExecInfo.lpParameters = TEXT("ACTIVATEFORCEPOLICY");
		}
		else
		{
			shExecInfo.lpParameters = TEXT("DESACTIVATEFORCEPOLICY");
		}
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

DWORD GetRemovePolicyValue()
{
	HKEY key;
	
	TCHAR szValue[2]=TEXT("0");
	DWORD size = sizeof(szValue);
	DWORD type=REG_SZ;	
	DWORD dwValue = 0;
	if (RegOpenKeyEx(HKEY_LOCAL_MACHINE,
		TEXT("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon"),
		NULL, KEY_READ, &key)==ERROR_SUCCESS){
		if (RegQueryValueEx(key,TEXT("scremoveoption"),NULL, &type,(LPBYTE) szValue, &size)==ERROR_SUCCESS)
		{
			dwValue = _tstoi(szValue);
		}
		RegCloseKey(key);
	}
	return dwValue;
}

INT_PTR CALLBACK WndProc_ForcePolicy(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam);

BOOL DialogForceSmartCardLogonPolicy()
{
	BOOL fReturn = FALSE;
	DWORD dwError = 0;
	if (IsElevated())
	{
		DialogBox(g_hinst, MAKEINTRESOURCE(IDD_DIALOGFORCEPOLICY), NULL, WndProc_ForcePolicy);
	}
	else
	{
	// elevate
		SHELLEXECUTEINFO shExecInfo;
		TCHAR szName[1024];
		GetModuleFileName(GetModuleHandle(NULL),szName, ARRAYSIZE(szName));
		shExecInfo.cbSize = sizeof(SHELLEXECUTEINFO);

		shExecInfo.fMask = SEE_MASK_NOCLOSEPROCESS;
		shExecInfo.hwnd = NULL;
		shExecInfo.lpVerb = TEXT("runas");
		shExecInfo.lpFile = szName;
		shExecInfo.lpParameters = TEXT("DIALOGFORCEPOLICY");
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

INT_PTR CALLBACK	WndProc_RemovePolicy(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam);

BOOL DialogRemovePolicy()
{
	BOOL fReturn = FALSE;
	DWORD dwError = 0;
	if (IsElevated())
	{
		DialogBox(g_hinst, MAKEINTRESOURCE(IDD_DIALOGREMOVEPOLICY), NULL, WndProc_RemovePolicy);
	}
	else
	{
	// elevate
		SHELLEXECUTEINFO shExecInfo;
		TCHAR szName[1024];
		GetModuleFileName(GetModuleHandle(NULL),szName, ARRAYSIZE(szName));
		shExecInfo.cbSize = sizeof(SHELLEXECUTEINFO);

		shExecInfo.fMask = SEE_MASK_NOCLOSEPROCESS;
		shExecInfo.hwnd = NULL;
		shExecInfo.lpVerb = TEXT("runas");
		shExecInfo.lpFile = szName;
		shExecInfo.lpParameters = TEXT("DIALOGREMOVEPOLICY");
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
