#include <Windows.h>
#include <tchar.h>
#include "global.h"
#include "EIDConfigurationWizard.h"

INT_PTR CALLBACK	WndProc_RemovePolicy(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam)
{
	int wmId;
	int wmEvent;
	DWORD dwValue;
	switch(message)
	{
	case WM_INITDIALOG:
		CenterWindow(hWnd);
		dwValue = GetRemovePolicyValue();
		switch(dwValue)
		{
		case 0:
			CheckRadioButton(hWnd, IDC_NOACTION, IDC_DISCONNECT, IDC_NOACTION);
			break;
		case 1:
			CheckRadioButton(hWnd, IDC_NOACTION, IDC_DISCONNECT, IDC_LOCK);
			break;
		case 2:
			CheckRadioButton(hWnd, IDC_NOACTION, IDC_DISCONNECT, IDC_LOGOFF);
			break;
		case 3:
			CheckRadioButton(hWnd, IDC_NOACTION, IDC_DISCONNECT, IDC_DISCONNECT);
			break;
		}
		break;
	case WM_COMMAND:
		wmId    = LOWORD(wParam);
		wmEvent = HIWORD(wParam);
		switch(wmId)
		{
		case IDOK:
			if (IsDlgButtonChecked(hWnd, IDC_NOACTION))
			{
				ChangeRemovePolicyElevated(0);
			}
			else if(IsDlgButtonChecked(hWnd, IDC_LOCK))
			{
				ChangeRemovePolicyElevated(1);
			}
			else if (IsDlgButtonChecked(hWnd, IDC_LOGOFF))
			{
				ChangeRemovePolicyElevated(2);
			}
			else if (IsDlgButtonChecked(hWnd, IDC_DISCONNECT))
			{
				ChangeRemovePolicyElevated(3);
			}
		case IDCANCEL:
			EndDialog(hWnd, 0); 
			return TRUE;
		}
	}
	return FALSE;
}