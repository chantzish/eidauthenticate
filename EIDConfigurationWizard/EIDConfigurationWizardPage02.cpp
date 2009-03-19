#include <windows.h>
#include <tchar.h>
#include <Commctrl.h>
#include <shellapi.h>

#include "global.h"
#include "EIDConfigurationWizard.h"
#include "ElevatedActions.h"

BOOL CALLBACK	WndProc_02ENABLE(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam)
{
	int wmId;
	int wmEvent;
	switch(message)
	{
	case WM_INITDIALOG:
		if (!fHasAlreadySmartCardCredential)
		{
			CenterWindow(GetParent(hWnd));
		}
		if (fGotoNewScreen)
		{
			PropSheet_SetCurSelByID(hWnd,IDD_03NEW);
		}
		break;
	case WM_COMMAND:
		wmId    = LOWORD(wParam);
		wmEvent = HIWORD(wParam);
		// Analyse les sélections de menu :
		switch (wmId)
		{	
		case IDC_02NEW:
			if (IsElevated())
			{
				fShowNewCertificatePanel = TRUE;
				PropSheet_SetCurSelByID(hWnd,IDD_03NEW);
			}
			else
			{
				// elevate
				SHELLEXECUTEINFO shExecInfo;
				TCHAR szName[1024];
				GetModuleFileName(GetModuleHandle(NULL),szName, ARRAYSIZE(szName));
				shExecInfo.cbSize = sizeof(SHELLEXECUTEINFO);

				shExecInfo.fMask = NULL;
				shExecInfo.hwnd = NULL;
				shExecInfo.lpVerb = TEXT("runas");
				shExecInfo.lpFile = szName;
				shExecInfo.lpParameters = TEXT("NEW");
				shExecInfo.lpDirectory = NULL;
				shExecInfo.nShow = SW_NORMAL;
				shExecInfo.hInstApp = NULL;

				if (ShellExecuteEx(&shExecInfo))
					PropSheet_PressButton(hWnd,PSBTN_CANCEL);
			}
			break;
		case IDC_02EXISTING:
			fShowNewCertificatePanel = FALSE;
			PropSheet_SetCurSelByID(hWnd,IDD_04CHECKS);
			break;

		}
		break;
	case WM_NOTIFY :
        LPNMHDR pnmh = (LPNMHDR)lParam;
        switch(pnmh->code)
        {
			case PSN_SETACTIVE :
				//this is an interior page
				if (fHasAlreadySmartCardCredential)
				{
					PropSheet_SetWizButtons(hWnd, PSWIZB_BACK);
				}
				else
				{
					PropSheet_SetWizButtons(hWnd, 0);
				}
				if (!IsElevated())
				{
					Button_SetElevationRequiredState(GetDlgItem(hWnd,IDC_02NEW),TRUE);
				}
				break;
		}
    }
	return FALSE;
}