#include <Windows.h>
#include <Commctrl.h>

#include "../EIDCardLibrary/CContainer.h"
#include "../EIDCardLibrary/CContainerHolderFactory.h"
#include "CContainerHolderXP.h"
#include "globalXP.h"
#include "EIDConfigurationWizardXP.h"

// from previous step
// credentials
extern CContainerHolderFactory<CContainerHolderTest> *pCredentialList;
extern DWORD dwWizardError;

void SetErrorMessage(HWND hWnd)
{
	LPTSTR Error;
	FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER|FORMAT_MESSAGE_FROM_SYSTEM,
		NULL,dwWizardError,0,(LPTSTR)&Error,0,NULL);
	SetWindowText(GetDlgItem(hWnd,IDC_WIZARDERROR),Error);
	LocalFree(Error);
}

INT_PTR CALLBACK	WndProc_07TESTRESULTNOTOK(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam)
{
	LPNMHDR pnmh = (LPNMHDR)lParam;
	switch(message)
	{
		case WM_INITDIALOG:
			break;
		case WM_NOTIFY :
			switch(pnmh->code)
			{
				case PSN_SETACTIVE:
					PropSheet_SetWizButtons(GetParent(hWnd), PSWIZB_BACK | PSWIZB_FINISH);
					SetErrorMessage(hWnd);
					break;
				case PSN_WIZBACK:
					// get to the test again (avoid test result page positive)
					PropSheet_PressButton(GetParent(hWnd), PSBTN_BACK);
					break;
				case PSN_WIZFINISH:
					if (pCredentialList)
					{
						delete pCredentialList;
						pCredentialList = NULL;
					}
					break;
			}
			break;
		
	}
	return FALSE;
}
