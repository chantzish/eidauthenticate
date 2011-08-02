#include <windows.h>
#include <tchar.h>
#include <Lm.h>

#include "../EIDCardLibrary/GPO.h"
#include "../EIDCardLibrary/Tracing.h"
#include "EIDConfigurationWizard.h"

extern HINSTANCE g_hinst;

VOID CenterWindow(HWND hWnd)
{
  RECT rcWindow;
  GetWindowRect(hWnd, &rcWindow);
  DWORD dwPosX = (GetSystemMetrics(SM_CXSCREEN)- (rcWindow.right - rcWindow.left)) / 2;
  DWORD dwPosY = (GetSystemMetrics(SM_CYSCREEN) - (rcWindow.bottom - rcWindow.top)) / 2;
  SetWindowPos(hWnd,
	       HWND_TOPMOST,
	       dwPosX, dwPosY,
	       0,
	       0,
	       SWP_NOSIZE | SWP_SHOWWINDOW);
}


VOID SetIcon(HWND hWnd)
{
	HMODULE hDll = LoadLibrary(TEXT("imageres.dll") );
	if (hDll)
	{
		HANDLE hbicon = LoadImage(hDll, MAKEINTRESOURCE(58),IMAGE_ICON, GetSystemMetrics(SM_CXICON), GetSystemMetrics(SM_CYICON), 0);
		if (hbicon)
			SendMessage(hWnd, WM_SETICON, ICON_BIG, (LPARAM) hbicon);
		hbicon = LoadImage(hDll, MAKEINTRESOURCE(58),IMAGE_ICON, GetSystemMetrics(SM_CXSMICON), GetSystemMetrics(SM_CYSMICON), 0);
		if (hbicon)
			SendMessage(hWnd, WM_SETICON, ICON_SMALL, (LPARAM) hbicon);
		FreeLibrary(hDll);
	}
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
		shExecInfo.nShow = SW_SHOW;
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
		shExecInfo.nShow = SW_SHOW;
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
