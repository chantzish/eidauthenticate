#include <Windows.h>
#include <Commctrl.h>

#include "../EIDCardLibrary/CContainer.h"
#include "../EIDCardLibrary/CContainerHolderFactory.h"
#include "CContainerHolder.h"
#include "global.h"
#include "EIDConfigurationWizard.h"

// from previous step
// credentials
extern CContainerHolderFactory<CContainerHolderTest> *pCredentialList;
extern DWORD dwCurrentCredential;
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
	int wmId;
	int wmEvent;
	LPNMHDR pnmh = (LPNMHDR)lParam;
	switch(message)
	{
		case WM_INITDIALOG:
			if (!IsElevated())
			{
				Button_SetElevationRequiredState(GetDlgItem(hWnd,IDC_07SENDREPORT),TRUE);
			}
			break;
		case WM_NOTIFY :
			switch(pnmh->code)
			{
				case PSN_SETACTIVE:
					PropSheet_SetWizButtons(hWnd, PSWIZB_BACK | PSWIZB_FINISH);
					SetErrorMessage(hWnd);
					break;
				case PSN_WIZBACK:
					// get to the test again (avoid test result page positive)
					PropSheet_PressButton(hWnd, PSBTN_BACK);
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
		case WM_COMMAND:
			wmId    = LOWORD(wParam);
			wmEvent = HIWORD(wParam);
			// Analyse les sélections de menu :
			switch (wmId)
			{	
				case IDC_07SENDREPORT:
					{
						TCHAR szEmail[256];
						GetWindowText(GetDlgItem(hWnd,IDC_07EMAIL),szEmail,ARRAYSIZE(szEmail));
						CContainerHolderTest* MyTest = pCredentialList->GetContainerHolderAt(dwCurrentCredential);
						CContainer* container = MyTest->GetContainer();
						if (!SendReport(dwWizardError, szEmail, container->GetCertificate()))
						{
							MessageBoxWin32Ex(GetLastError(), hWnd);
						}
						else
						{
							//success !
							MessageBoxWin32Ex(0, hWnd);
						}
					}
					break;
			}
			break;
		
	}
	return FALSE;
}
