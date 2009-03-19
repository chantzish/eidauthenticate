#include <windows.h>
#include <tchar.h>
#include <credentialprovider.h>

#include "global.h"
#include "EIDConfigurationWizard.h"
#include "../EIDCardLibrary/EIDCardLibrary.h"
#include "../EIDCardLibrary/Package.h"


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
BOOL CALLBACK	WndProc_01MAIN(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam)
{
	int wmId;
	int wmEvent;
	switch(message)
	{
	case WM_INITDIALOG:
		CenterWindow(GetParent(hWnd));
		if (fGotoNewScreen)
		{
			PropSheet_SetCurSelByID(hWnd,IDD_02ENABLE);
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
			if (IDYES == MessageBox(hWnd,TEXT("Sure ?"),TEXT(""),MB_ICONWARNING|MB_YESNO))
			{
				if (!LsaEIDRemoveStoredCredential(NULL))
				{
					MessageBox(hWnd,TEXT("Unable to remove"),TEXT(""),MB_ICONEXCLAMATION);
					break;
				}
				// delete
				PropSheet_PressButton(hWnd,PSBTN_CANCEL);
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