#include <windows.h>
#include <tchar.h>
#include <credentialprovider.h>

#include "EIDConfigurationWizard.h"
#include "ElevatedActions.h"

#include "../EIDCardLibrary/EIDCardLibrary.h"
#include "../EIDCardLibrary/Package.h"
#include "../EIDCardLibrary/Registration.h"

#pragma comment(lib,"comctl32")

#ifdef UNICODE
#if defined _M_IX86
#pragma comment(linker,"/manifestdependency:\"type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' processorArchitecture='x86' publicKeyToken='6595b64144ccf1df' language='*'\"")
#elif defined _M_IA64
#pragma comment(linker,"/manifestdependency:\"type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' processorArchitecture='ia64' publicKeyToken='6595b64144ccf1df' language='*'\"")
#elif defined _M_X64
#pragma comment(linker,"/manifestdependency:\"type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' processorArchitecture='amd64' publicKeyToken='6595b64144ccf1df' language='*'\"")
#else
#pragma comment(linker,"/manifestdependency:\"type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' processorArchitecture='*' publicKeyToken='6595b64144ccf1df' language='*'\"")
#endif
#endif

BOOL CALLBACK	WndProc_01MAIN(HWND, UINT, WPARAM, LPARAM);
BOOL CALLBACK	WndProc_02ENABLE(HWND, UINT, WPARAM, LPARAM);
BOOL CALLBACK	WndProc_03NEW(HWND, UINT, WPARAM, LPARAM);
BOOL CALLBACK	WndProc_04CHECKS(HWND, UINT, WPARAM, LPARAM);
BOOL CALLBACK	WndProc_05PASSWORD(HWND, UINT, WPARAM, LPARAM);

BOOL fHasAlreadySmartCardCredential = FALSE;
BOOL fShowNewCertificatePanel;
BOOL fGotoNewScreen = FALSE;
HINSTANCE g_hinst;


void NTAPI DllRegister()
{
	EIDConfigurationWizardDllRegister();
}

void NTAPI DllUnRegister()
{
	EIDConfigurationWizardDllUnRegister();
}

int APIENTRY _tWinMain(HINSTANCE hInstance,
                     HINSTANCE hPrevInstance,
                     LPTSTR    lpCmdLine,
                     int       nCmdShow)
{
	UNREFERENCED_PARAMETER(hPrevInstance);
	UNREFERENCED_PARAMETER(lpCmdLine);

	if (!IsEIDPackageAvailable())
	{
		MessageBox(NULL,TEXT("Authentication package not available"),TEXT("Error"),MB_ICONERROR);
		return -1;
	}
	g_hinst = hInstance;
	int iNumArgs;
	LPWSTR *pszCommandLine =  CommandLineToArgvW(lpCmdLine,&iNumArgs);

	if (iNumArgs >= 1)
	{
		if (_tcscmp(pszCommandLine[0],TEXT("NEW")) == 0)
		{
			fGotoNewScreen = TRUE;
		}
		if (iNumArgs >= 3)
		{
			if (_tcscmp(pszCommandLine[0],TEXT("RENAME")) == 0)
			{
				return RenameAccount(pszCommandLine[1],pszCommandLine[2]);
			}
		}
	}

	HPROPSHEETPAGE ahpsp[5];

	fHasAlreadySmartCardCredential = TRUE;

	PROPSHEETPAGE psp = { sizeof(psp) };   
	psp.hInstance = hInstance;
	psp.dwFlags =  PSP_USEHEADERTITLE;
	psp.lParam = 0;//(LPARAM) &wizdata;
	
	psp.pszHeaderTitle = TEXT("Credential managment");
	psp.pszTemplate = MAKEINTRESOURCE(IDD_01MAIN);
	psp.pfnDlgProc = WndProc_01MAIN;
	ahpsp[0] = CreatePropertySheetPage(&psp);

	psp.pszHeaderTitle = TEXT("Configure smart card logon");
	psp.pszTemplate = MAKEINTRESOURCE(IDD_02ENABLE);
	psp.pfnDlgProc = WndProc_02ENABLE;
	ahpsp[1] = CreatePropertySheetPage(&psp);

	psp.pszHeaderTitle = TEXT("Configure a smart card");
	psp.pszTemplate = MAKEINTRESOURCE(IDD_03NEW);
	psp.pfnDlgProc = WndProc_03NEW;
	ahpsp[2] = CreatePropertySheetPage(&psp);

	psp.pszHeaderTitle = TEXT("Check the status of the smart card");
	psp.pszTemplate = MAKEINTRESOURCE(IDD_04CHECKS);
	psp.pfnDlgProc = WndProc_04CHECKS;
	ahpsp[3] = CreatePropertySheetPage(&psp);

	psp.pszHeaderTitle = TEXT("Enter your password");
	psp.pszTemplate = MAKEINTRESOURCE(IDD_05PASSWORD);
	psp.pfnDlgProc = WndProc_05PASSWORD;
	ahpsp[4] = CreatePropertySheetPage(&psp);

	PROPSHEETHEADER psh = { sizeof(psh) };
	psh.hInstance = hInstance;
	psh.hwndParent = NULL;
	psh.phpage = ahpsp;
	psh.dwFlags = PSH_WIZARD | PSH_AEROWIZARD | PSH_USEHICON;
	psh.pszbmWatermark = 0;
	psh.pszbmHeader = 0;
	psh.nStartPage = 1;
	psh.nPages = ARRAYSIZE(ahpsp);
	psh.pszCaption = TEXT("Smart Card Logon Configuration");

	HMODULE hDll = LoadLibrary(TEXT("imageres.dll") );
	psh.hIcon = LoadIcon(hDll, MAKEINTRESOURCE(58));
	FreeLibrary(hDll);

	fHasAlreadySmartCardCredential = LsaEIDHasStoredCredential(NULL);

	if (fHasAlreadySmartCardCredential)
	{
		// 01MAIN
		psh.nStartPage = 0;
	}
	else
	{
		// 02ENABLE
		psh.nStartPage = 1;
	}
	PropertySheet(&psh);
	//_CrtDumpMemoryLeaks();
    return 0;

}

