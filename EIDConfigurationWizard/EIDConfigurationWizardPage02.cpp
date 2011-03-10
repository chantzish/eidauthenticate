#include <windows.h>
#include <tchar.h>
#include <Commctrl.h>
#include <shellapi.h>

#include "global.h"
#include "EIDConfigurationWizard.h"
#include "../EIDCardLibrary/CertificateUtilities.h"
#include "../EIDCardLibrary/Tracing.h"

INT_PTR CALLBACK	WndProc_02ENABLE(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam)
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
		if (!IsElevated())
		{
			Button_SetElevationRequiredState(GetDlgItem(hWnd,IDC_02NEW),TRUE);
		}
		{
			TCHAR szNote[256] = TEXT("");
			LoadString(g_hinst,IDS_02NEWNOTE, szNote, ARRAYSIZE(szNote));
			Button_SetNote(GetDlgItem(hWnd,IDC_02NEW),szNote);
			LoadString(g_hinst,IDS_02EXISTINGNOTE, szNote, ARRAYSIZE(szNote));
			Button_SetNote(GetDlgItem(hWnd,IDC_02EXISTING),szNote);
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
				if (AskForCard(szReader, dwReaderSize, szCard, dwCardSize))
				{
					//next screen
					fShowNewCertificatePanel = TRUE;
					PropSheet_SetCurSelByID(hWnd,IDD_03NEW);
				}
				else
				{
					LONG lReturn = GetLastError();
					if (lReturn != SCARD_W_CANCELLED_BY_USER)
					{
						MessageBoxWin32(lReturn);
					}
				}
			}
			else
			{
				// elevate
				SHELLEXECUTEINFO shExecInfo;
				TCHAR szName[1024];
				TCHAR szParameter[1024] = TEXT("NEW_USERNAME ");
				DWORD dwSize = ARRAYSIZE(szParameter) - (DWORD) _tcsclen(szParameter);
				GetUserName(szParameter + ARRAYSIZE(szParameter) - dwSize, &dwSize);

				GetModuleFileName(GetModuleHandle(NULL),szName, ARRAYSIZE(szName));
				shExecInfo.cbSize = sizeof(SHELLEXECUTEINFO);

				shExecInfo.fMask = NULL;
				shExecInfo.hwnd = NULL;
				shExecInfo.lpVerb = TEXT("runas");
				shExecInfo.lpFile = szName;
				shExecInfo.lpParameters = szParameter;
				shExecInfo.lpDirectory = NULL;
				shExecInfo.nShow = SW_NORMAL;
				shExecInfo.hInstApp = NULL;

				if (ShellExecuteEx(&shExecInfo))
					PropSheet_PressButton(hWnd,PSBTN_CANCEL);
			}
			break;
		case IDC_02EXISTING:
			if (AskForCard(szReader, dwReaderSize, szCard, dwCardSize))
			{
				//next screen
				fShowNewCertificatePanel = FALSE;
				PropSheet_SetCurSelByID(hWnd,IDD_04CHECKS);
			}
			else
			{
				LONG lReturn = GetLastError();
				if (lReturn != SCARD_W_CANCELLED_BY_USER)
				{
					MessageBoxWin32(lReturn);
				}
			}
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
				break;
			case NM_CLICK:
			case NM_RETURN:
				{
					PNMLINK pNMLink = (PNMLINK)lParam;
					LITEM item = pNMLink->item;
					if ((((LPNMHDR)lParam)->hwndFrom == GetDlgItem(hWnd,IDC_SYSLINKHELP)) && (item.iLink == 0))
					{
						ShellExecute(NULL, L"open", item.szUrl, NULL, NULL, SW_SHOW);
					}
					break;
				}

		}
    }
	return FALSE;
}