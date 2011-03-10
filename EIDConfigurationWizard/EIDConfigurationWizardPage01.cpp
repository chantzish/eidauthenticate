#include <windows.h>
#include <tchar.h>
#include <credentialprovider.h>

#include "global.h"
#include "resource.h"
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
	int wmId;
	int wmEvent;
	switch(message)
	{
	case WM_INITDIALOG:
		{
			CenterWindow(GetParent(hWnd));
		}
		break;
	case WM_COMMAND:
		wmId    = LOWORD(wParam);
		wmEvent = HIWORD(wParam);
		// Analyse les sélections de menu :
		switch (wmId)
		{	
		case IDC_01CHANGE:
			 PropSheet_SetCurSelByID(hWnd,IDD_02ENABLE);

			break;
		case IDC_01DELETE:
			{
				TCHAR szMessage[256] = TEXT("");
				LoadString(g_hinst,IDS_AREYOUSURE,szMessage,ARRAYSIZE(szMessage));
				if (IDYES == MessageBox(hWnd,szMessage,TEXT(""),MB_ICONWARNING|MB_YESNO))
				{
					if (!LsaEIDRemoveStoredCredential(NULL))
					{
						MessageBoxWin32(GetLastError());
						break;
					}
					// delete
					PropSheet_PressButton(hWnd,PSBTN_CANCEL);
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
				PropSheet_SetWizButtons(hWnd, 0);
				break;
		}
    }
	return FALSE;
}