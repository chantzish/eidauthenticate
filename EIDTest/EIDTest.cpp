// EIDCardLibraryTest.cpp : définit le point d'entrée pour l'application.
//
#include <ntstatus.h>
#define WIN32_NO_STATUS 1
#include <windows.h>
#include <tchar.h>

#include <Ntsecapi.h>

#define SECURITY_WIN32
#include <sspi.h>

#include <ntsecpkg.h>

#include <Commctrl.h>
#include <crtdbg.h>

#include "stdafx.h"

#include "EIDTest.h"
#include "CSmartCardNotifierTest.h"
#include "CompleteTokenTest.h"
#include "CompleteProfileTest.h"
#include "GPOTest.h"
#include "CContainerTest.h"
#include "PackageTest.h"
#include "EIDAuthenticationPackageTest.h"
#include "EIDCredentialProviderTest.h"
#include "EIDTestUtil.h"
#include "EIDTestInfo.h"
#include "CertificateValidationTest.h"
#include "StoredCredentialManagementTest.h"
#include "../EIDCardLibrary/Registration.h"

// Variables globales :
HINSTANCE hInst;								// instance actuelle
HWND hMainWnd;
// Pré-déclarations des fonctions incluses dans ce module de code :

BOOL CALLBACK	WndProc(HWND, UINT, WPARAM, LPARAM);

int APIENTRY _tWinMain(HINSTANCE hInstance,
                     HINSTANCE hPrevInstance,
                     LPTSTR    lpCmdLine,
                     int       nCmdShow)
{
	UNREFERENCED_PARAMETER(hPrevInstance);
	UNREFERENCED_PARAMETER(lpCmdLine);
	hInst = hInstance;
	_CrtSetDbgFlag(_CRTDBG_ALLOC_MEM_DF|_CRTDBG_CHECK_ALWAYS_DF|_CRTDBG_CHECK_CRT_DF|_CRTDBG_DELAY_FREE_MEM_DF);

    DialogBox (hInst, 
                            MAKEINTRESOURCE (IDD_MAIN), 
                            0, 
                            WndProc);
	//_CrtDumpMemoryLeaks();
    return 0;

}


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
BOOL CALLBACK WndProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam)
{
	int wmId, wmEvent;
	SHSTOCKICONINFO sii = {0};
	HICON g_hShieldIcon;
	MENUITEMINFO mii= {0};
	switch (message)
	{
	case WM_INITDIALOG:
		hMainWnd = hWnd;
		
		// shield icon
		sii.cbSize = sizeof(sii);
		SHGetStockIconInfo(SIID_SHIELD, SHGFI_ICON | SHGFI_SMALLICON, &sii);
		g_hShieldIcon = sii.hIcon;
		mii.cbSize = sizeof(mii);
		mii.fMask = MIIM_BITMAP | MIIM_DATA;
		mii.hbmpItem = HBMMENU_CALLBACK;
		mii.dwItemData = (ULONG_PTR)g_hShieldIcon;
		
		SetMenuItemInfo(GetMenu(hWnd), IDM_CRED_RP_TRIGGER, FALSE, &mii);
		SetMenuItemInfo(GetMenu(hWnd), IDM_INFO_TRACING, FALSE, &mii);

		return TRUE;
		break;

	case WM_MEASUREITEM:
	{
		LPMEASUREITEMSTRUCT pms = (LPMEASUREITEMSTRUCT)lParam;
		if (pms->CtlType == ODT_MENU) {
			pms->itemWidth  = 16;
			pms->itemHeight = 16;
			return TRUE;
		} 
	}
	break;

	case WM_DRAWITEM: 
	{
	   LPDRAWITEMSTRUCT pds = (LPDRAWITEMSTRUCT)lParam;
	   if (pds->CtlType == ODT_MENU) {
		   DrawIconEx(pds->hDC, pds->rcItem.left - 15, 
			   pds->rcItem.top, 
			   (HICON)pds->itemData, 
			   16, 16, 0, NULL, DI_NORMAL);
		   return TRUE;
	   }
	}
	break; 

	case WM_CLOSE:
         EndDialog(hWnd, IDOK);
		return TRUE;
	case WM_COMMAND:
		wmId    = LOWORD(wParam);
		wmEvent = HIWORD(wParam);
		// Analyse les sélections de menu :
		switch (wmId)
		{
	// test thread detection function	
		case IDM_STARTWAITTHREAD:
			Menu_STARTWAITTHREAD();
			break;
		case IDM_STOPWAITTHREAD:
			Menu_STOPWAITTHREAD();
			break;
	// test authentification package
		case IDM_AP_TOKEN:
			 Menu_AP_Token();
			break;
		case IDM_AP_PROFILE:
			Menu_AP_Profile();
			break;
		case IDM_AP_REGISTRATION:
			Menu_TestPackageRegistration();
			break;
		case IDM_AP_PROTECT:
			menu_AP_Protect();
			break;
		case IDM_AP_LOAD:
			Menu_TestPackageLoad();
			break;
		case IDM_AP_GPO:
			Menu_AP_GPO();
			break;
		case IDM_CRED_RP_TRACE:
			menu_TRACE_REMOVE_POLICY();
			break;
		case IDM_CRED_RP_TRIGGER:
			menu_CRED_RP_Trigger();
			break;
		case IDM_CRED_UI:
			Menu_CREDENTIALUID();
			break;
		case IDM_CRED_UI_ADMIN:
			Menu_CREDENTIALUID_ADMIN();
			break;
		case IDM_CRED_LIST:
			menu_CREDENTIAL_List();
			break;
		case IDM_CRED_CERT:
			menu_CREDENTIAL_Certificate();
			break;
		case IDM_CRED_TILE:
			menu_CRED_CallAuthPackage();
			break;
		case IDM_CRED_COM:
			menu_CRED_COM();
			break;
		case IDM_PASS_CREATE:
			menu_CREDMGMT_CreateStoredCredential();
			break;
		case IDM_PASS_UPDATE:
			menu_CREDMGMT_UpdateStoredCredential();
			break;
		case IDM_PASS_DELETE:
			menu_CREDMGMT_DeleteStoredCredential();
			break;
		case IDM_PASS_RETRIEVE:
			menu_CREDMGMT_RetrieveStoredCredential();
			break;
		case IDM_REG_AP:
			EIDAuthenticationPackageDllRegister();
			break;
		case IDM_UNREG_AP:
			EIDAuthenticationPackageDllUnRegister();
			break;
		case IDM_REG_CP:
			EIDCredentialProviderDllRegister();
			break;
		case IDM_UNREG_CP:
			EIDCredentialProviderDllUnRegister();
			break;
		case IDM_REG_PF:
			EIDPasswordChangeNotificationDllRegister();
			break;
		case IDM_UNREG_PF:
			EIDPasswordChangeNotificationDllUnRegister();
			break;
		case IDM_REG_WIZ:
			EIDConfigurationWizardDllRegister();
			break;
		case IDM_UNREG_WIZ:
			EIDConfigurationWizardDllUnRegister();
			break;
		case IDM_UTIL_LIST:
			menu_UTIL_ListCertificates();
			break;
		case IDM_UTIL_CERT:
			menu_UTIL_CreateCert();
			break;
		case IDM_UTIL_SHOWSD:
			menu_UTIL_ShowSecurityDescriptor();
			break;
		case IDM_UTIL_DELETE:
			menu_UTIL_DeleteOneCertificate();
			break;
		case IDM_UTIL_CLEAR:
			menu_UTIL_ClearCard();
			break;
		case IDM_INFO_TRACING:
			menu_TRACE_TRACING();
			break;
		case IDM_INFO_CSP:
			menu_INFO_Provider();
			break;
		case IDM_INFO_HASHSHA1:
			menu_INFO_ComputeHashSha1();
			break;
		case IDM_INFO_HASHNT:
			menu_INFO_ComputeHashNT();
			break;
		case IDM_EXIT:
			DestroyWindow(hWnd);
			break;
		default:
			return FALSE;
		}
		
		
		
	//_CrtDumpMemoryLeaks();
		break;
	default:
		return FALSE;
	}
	return FALSE;
}
