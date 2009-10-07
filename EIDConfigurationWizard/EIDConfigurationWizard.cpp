#include <windows.h>
#include <tchar.h>
#include <credentialprovider.h>

#include "EIDConfigurationWizard.h"
#include "global.h"

#include "../EIDCardLibrary/EIDCardLibrary.h"
#include "../EIDCardLibrary/Package.h"
#include "../EIDCardLibrary/Registration.h"
#include "../EIDCardLibrary/CertificateUtilities.h"
#include "../EIDCardLibrary/CertificateValidation.h"

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

INT_PTR CALLBACK	WndProc_01MAIN(HWND, UINT, WPARAM, LPARAM);
INT_PTR CALLBACK	WndProc_02ENABLE(HWND, UINT, WPARAM, LPARAM);
INT_PTR CALLBACK	WndProc_03NEW(HWND, UINT, WPARAM, LPARAM);
INT_PTR CALLBACK	WndProc_04CHECKS(HWND, UINT, WPARAM, LPARAM);
INT_PTR CALLBACK	WndProc_05PASSWORD(HWND, UINT, WPARAM, LPARAM);

BOOL fHasAlreadySmartCardCredential = FALSE;
BOOL fShowNewCertificatePanel;
BOOL fGotoNewScreen = FALSE;
HINSTANCE g_hinst;
WCHAR szReader[256];
DWORD dwReaderSize = ARRAYSIZE(szReader);
WCHAR szCard[256];
DWORD dwCardSize = ARRAYSIZE(szCard);

int APIENTRY _tWinMain(HINSTANCE hInstance,
                     HINSTANCE hPrevInstance,
                     LPTSTR    lpCmdLine,
                     int       nCmdShow)
{
	UNREFERENCED_PARAMETER(hPrevInstance);
	UNREFERENCED_PARAMETER(lpCmdLine);

	if (!IsEIDPackageAvailable())
	{
		TCHAR szMessage[256] = TEXT("");
		LoadString(g_hinst,IDS_EIDNOTAVAILABLE, szMessage, ARRAYSIZE(szMessage));
		MessageBox(NULL,szMessage,TEXT("Error"),MB_ICONERROR);
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
		else if (_tcscmp(pszCommandLine[0],TEXT("ACTIVATEREMOVEPOLICY")) == 0)
		{
			ChangeRemovePolicy(TRUE);
			return 0;
		} 
		else if (_tcscmp(pszCommandLine[0],TEXT("DESACTIVATEREMOVEPOLICY")) == 0)
		{
			ChangeRemovePolicy(FALSE);
			return 0;
		} 
		else if (_tcscmp(pszCommandLine[0],TEXT("ACTIVATEFORCEPOLICY")) == 0)
		{
			ChangeForceSmartCardLogonPolicy(TRUE);
			return 0;
		} 
		else if (_tcscmp(pszCommandLine[0],TEXT("DESACTIVATEFORCEPOLICY")) == 0)
		{
			ChangeForceSmartCardLogonPolicy(FALSE);
			return 0;
		} 
		else if (_tcscmp(pszCommandLine[0],TEXT("ENABLENOEKU")) == 0)
		{
			DWORD dwValue = 1;
			RegSetKeyValue(	HKEY_LOCAL_MACHINE, 
				TEXT("SOFTWARE\\Policies\\Microsoft\\Windows\\SmartCardCredentialProvider"),
				TEXT("AllowCertificatesWithNoEKU"), REG_DWORD, &dwValue,sizeof(dwValue));
		}
		else if (_tcscmp(pszCommandLine[0],TEXT("TRUST")) == 0)
		{
			if (iNumArgs < 2)
			{
				return 0;
			}
			DWORD dwSize = 0;
			CryptStringToBinary(pszCommandLine[1],0,CRYPT_STRING_BASE64,NULL,&dwSize,NULL,NULL);
			PBYTE pbCertificate = (PBYTE) EIDAlloc(dwSize);
			CryptStringToBinary(pszCommandLine[1],0,CRYPT_STRING_BASE64,pbCertificate,&dwSize,NULL,NULL);
			PCCERT_CONTEXT pCertContext = CertCreateCertificateContext(X509_ASN_ENCODING,pbCertificate, dwSize);
			if (pCertContext)
			{
				MakeTrustedCertifcate(pCertContext);
				CertFreeCertificateContext(pCertContext);
			}
			EIDFree(pbCertificate);
			return 0;
		} 
		else if (_tcscmp(pszCommandLine[0],TEXT("RENAMEUSER")) == 0)
		{
			RenameAccount(lpCmdLine + 11);
			return 0;
		}
	}

	HPROPSHEETPAGE ahpsp[5];
	TCHAR szTitle[256] = TEXT("");
	fHasAlreadySmartCardCredential = TRUE;

	PROPSHEETPAGE psp = { sizeof(psp) };   
	psp.hInstance = hInstance;
	psp.dwFlags =  PSP_USEHEADERTITLE;
	psp.lParam = 0;//(LPARAM) &wizdata;
	
	LoadString(g_hinst,IDS_TITLE0, szTitle, ARRAYSIZE(szTitle));
	psp.pszHeaderTitle = szTitle;
	psp.pszTemplate = MAKEINTRESOURCE(IDD_01MAIN);
	psp.pfnDlgProc = WndProc_01MAIN;
	ahpsp[0] = CreatePropertySheetPage(&psp);

	LoadString(g_hinst,IDS_TITLE1, szTitle, ARRAYSIZE(szTitle));
	psp.pszHeaderTitle = szTitle;
	psp.pszTemplate = MAKEINTRESOURCE(IDD_02ENABLE);
	psp.pfnDlgProc = WndProc_02ENABLE;
	ahpsp[1] = CreatePropertySheetPage(&psp);

	LoadString(g_hinst,IDS_TITLE2, szTitle, ARRAYSIZE(szTitle));
	psp.pszHeaderTitle = szTitle;
	psp.pszTemplate = MAKEINTRESOURCE(IDD_03NEW);
	psp.pfnDlgProc = WndProc_03NEW;
	ahpsp[2] = CreatePropertySheetPage(&psp);

	LoadString(g_hinst,IDS_TITLE3, szTitle, ARRAYSIZE(szTitle));
	psp.pszHeaderTitle = szTitle;
	psp.pszTemplate = MAKEINTRESOURCE(IDD_04CHECKS);
	psp.pfnDlgProc = WndProc_04CHECKS;
	ahpsp[3] = CreatePropertySheetPage(&psp);

	LoadString(g_hinst,IDS_TITLE4, szTitle, ARRAYSIZE(szTitle));
	psp.pszHeaderTitle = szTitle;
	psp.pszTemplate = MAKEINTRESOURCE(IDD_05PASSWORD);
	psp.pfnDlgProc = WndProc_05PASSWORD;
	ahpsp[4] = CreatePropertySheetPage(&psp);

	PROPSHEETHEADER psh = { sizeof(psh) };
	psh.hInstance = hInstance;
	psh.hwndParent = NULL;
	psh.phpage = ahpsp;
	psh.dwFlags = PSH_WIZARD | PSH_AEROWIZARD | PSH_USEHICON ;
	psh.pszbmWatermark = 0;
	psh.pszbmHeader = 0;
	psh.nStartPage = 1;
	psh.nPages = ARRAYSIZE(ahpsp);
	psh.hIcon = NULL;
	LoadString(g_hinst,IDS_CAPTION, szTitle, ARRAYSIZE(szTitle));
	psh.pszCaption = szTitle;

	HMODULE hDll = LoadLibrary(TEXT("imageres.dll") );
	if (hDll)
	{
		psh.hIcon = LoadIcon(hDll, MAKEINTRESOURCE(58));
		FreeLibrary(hDll);
	}

	fHasAlreadySmartCardCredential = LsaEIDHasStoredCredential(NULL);

	 if (fGotoNewScreen)
	{
		if (AskForCard(szReader, dwReaderSize, szCard, dwCardSize))
		{
			psh.nStartPage = 2;
		}
		else
		{
			psh.nStartPage = 1;
		}
	}
	else if (fHasAlreadySmartCardCredential)
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

