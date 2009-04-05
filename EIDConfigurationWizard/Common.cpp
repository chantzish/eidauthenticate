#include <windows.h>
#include <tchar.h>

#include "../EIDCardLibrary/GPO.h"
#include "../EIDCardLibrary/Tracing.h"

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

BOOL ChangeRemovePolicy(BOOL fActivate)
{
	TCHAR szValueActivated[2]=TEXT("1");
	TCHAR szValueDesactivated[2]=TEXT("0");
	TCHAR *szValue;
	LONG lReturn;
	DWORD dwError = 0;
	SC_HANDLE hService = NULL;
	SC_HANDLE hServiceManager = NULL;
	SERVICE_STATUS ServiceStatus;
	if (fActivate)
	{
		szValue = szValueActivated;
	}
	else
	{
		szValue = szValueDesactivated;
	}
	__try
	{
		lReturn = RegSetKeyValue(HKEY_LOCAL_MACHINE, 
			TEXT("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon"),
			TEXT("scremoveoption"), REG_SZ, szValue,sizeof(TCHAR)*ARRAYSIZE(szValueActivated));
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
		if (fActivate)
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
	if (dwError)
		MessageBoxWin32(dwError);
	return dwError == 0;
}

BOOL ChangeForceSmartCardLogonPolicy(BOOL fActivate)
{
	DWORD dwValue;
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