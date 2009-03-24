#include <windows.h>
#include <tchar.h>
#include <lm.h>

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

DWORD RenameAccount(__in_opt PTSTR szFromAccount, __in PTSTR szToAccount)
{
	NET_API_STATUS nStatus;
	USER_INFO_0 UserInfo;
	DWORD dwError = 0;
	TCHAR szUserName[1024];
	DWORD dwSize = ARRAYSIZE(szUserName);
	
	__try
	{
		/*if (!szFromAccount)
		{
			GetUserName(szUserName, &dwSize);
			szFromAccount = szUserName;
		}
		if (IsElevated())
		{


			UserInfo.usri0_name = szToAccount;
			nStatus = NetUserSetInfo(NULL, szFromAccount, 0, (PBYTE) &UserInfo, NULL);
			if (nStatus != NERR_Success)
			{
				__leave;
			}
			//LRESULT lStatus = SendMessage(HWND_BROADCAST,WM_SETTINGCHANGE,0,(LPARAM) "Environment");
		}
		else
		{
			// elevate
			SHELLEXECUTEINFO shExecInfo;
			TCHAR szName[1024];
			TCHAR szCommandLine[1024];
			GetModuleFileName(GetModuleHandle(NULL),szName, ARRAYSIZE(szName));
			_stprintf_s(szCommandLine, ARRAYSIZE(szCommandLine),TEXT("RENAME \"%s\" \"%s\""), szFromAccount, szToAccount);
			shExecInfo.cbSize = sizeof(SHELLEXECUTEINFO);

			shExecInfo.fMask = NULL;
			shExecInfo.hwnd = NULL;
			shExecInfo.lpVerb = TEXT("runas");
			shExecInfo.lpFile = szName;
			shExecInfo.lpParameters = szCommandLine;
			shExecInfo.lpDirectory = NULL;
			shExecInfo.nShow = SW_NORMAL;
			shExecInfo.hInstApp = NULL;

			dwError = ShellExecuteEx(&shExecInfo);
		}*/
		CoInitializeEx(NULL, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE);
		SHELLEXECUTEINFO shExecInfo;
		shExecInfo.fMask = NULL;
		shExecInfo.hwnd = NULL;
		shExecInfo.lpVerb = NULL;
		shExecInfo.lpFile = TEXT("control");
		shExecInfo.lpParameters = TEXT("/name Microsoft.UserAccounts");
		shExecInfo.lpDirectory = NULL;
		shExecInfo.nShow = SW_NORMAL;
		shExecInfo.hInstApp = NULL;

		dwError = ShellExecuteEx(&shExecInfo);
	}
	__finally
	{
	}
	return dwError;
}