#include <Windows.h>
#include <tchar.h>
#include "global.h"
#include "../EIDCardLibrary/GPO.h"
#include "EIDConfigurationWizard.h"

INT_PTR CALLBACK WndProc_ForcePolicy(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam)
{
	int wmId;
	int wmEvent;
	switch(message)
	{
	case WM_INITDIALOG:
		CenterWindow(hWnd);
		if (GetPolicyValue(scforceoption) > 0)
		{
			CheckRadioButton(hWnd, IDC_FORCEDISABLE, IDC_FORCEENABLE, IDC_FORCEENABLE);
		}
		else
		{
			CheckRadioButton(hWnd, IDC_FORCEDISABLE, IDC_FORCEENABLE, IDC_FORCEDISABLE);
		}
		break;
	case WM_COMMAND:
		wmId    = LOWORD(wParam);
		wmEvent = HIWORD(wParam);
		switch(wmId)
		{
		case IDOK:
			ChangeForceSmartCardLogonPolicy(IsDlgButtonChecked(hWnd, IDC_FORCEENABLE));
		case IDCANCEL:
			EndDialog(hWnd, 0); 
			return TRUE;
		}
	}
	return FALSE;
}