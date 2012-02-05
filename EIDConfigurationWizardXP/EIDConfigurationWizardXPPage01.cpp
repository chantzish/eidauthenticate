#include <windows.h>
#include <tchar.h>
#include <credentialprovider.h>

#include "globalXP.h"
#include "EIDConfigurationWizardXP.h"
#include "../EIDCardLibrary/EIDCardLibrary.h"
#include "../EIDCardLibrary/Package.h"
#include "../EIDCardLibrary/Tracing.h"


//
//  FONCTION : WndProc(HWND, UINT, WPARAM, LPARAM)
//
//  BUT :  traite les messages pour la fenêtre principale.
//
//  WM_COMMAND	- traite le menu de l'application
//  WM_PAINT	- dessine la fenêtre principale
//  WM_DESTROY	- génère un message d'arrêt et retourne
//
//
INT_PTR CALLBACK	WndProc_01MAIN(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam)
{
	switch(message)
	{
	case WM_INITDIALOG:
		{
			CenterWindow(GetParent(hWnd));
			CheckDlgButton(hWnd, IDC_01CHANGE, BST_CHECKED);
		}
		break;
	case WM_NOTIFY :
        LPNMHDR pnmh = (LPNMHDR)lParam;
        switch(pnmh->code)
        {
			case PSN_SETACTIVE :
				//this is an interior page
				PropSheet_SetWizButtons(GetParent(hWnd), PSWIZB_NEXT);
				break;
			case PSN_WIZNEXT:
				{
					if (IsDlgButtonChecked(hWnd, IDC_01DELETE) == BST_CHECKED)
					{
						TCHAR szMessage[256] = TEXT("");
						LoadString(g_hinst,IDS_AREYOUSURE,szMessage,ARRAYSIZE(szMessage));
						if (IDYES == MessageBox(hWnd,szMessage,TEXT(""),MB_ICONWARNING|MB_YESNO))
						{
							if (!LsaEIDRemoveStoredCredential(NULL))
							{
								MessageBoxWin32Ex(GetLastError(),hWnd);
							}
							else
							{
								// delete
								PropSheet_PressButton(GetParent(hWnd),PSBTN_CANCEL);
							}
						}
						SetWindowLongPtr(hWnd,DWLP_MSGRESULT,-1);
						return TRUE;
					}
				}
				break;
		}
    }
	return FALSE;
}