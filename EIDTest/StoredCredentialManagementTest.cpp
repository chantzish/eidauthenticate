#include <windows.h>
#include <tchar.h>
#include <Ntsecapi.h>
#include <credentialprovider.h>

#include "EIDTestUIUtil.h"
#include "../EIDCardLibrary/EIDCardLibrary.h"
#include "../EIDCardLibrary/StoredCredentialManagement.h"
#include "../EIDCardLibrary/Package.h"
#include "../EIDCardLibrary/CertificateUtilities.h"
#include "../EIDCardLibrary/Tracing.h"

extern HWND hMainWnd;


void menu_CREDMGMT_CreateStoredCredential(BOOL fCrypt)
{
	WCHAR szUserName[256];
	WCHAR szComputerName[256];
	WCHAR szReader[256];
	WCHAR szCard[256];
	WCHAR szContainer[256];
	WCHAR szProvider[256];
	WCHAR szPin[256];
	DWORD dwKeySpec = 0;
	PCCERT_CONTEXT Context = NULL;

	if (AskForCard(szReader,256,szCard,256)) {
		if (Context = SelectCerts(szReader,szCard,szProvider, 256, szContainer,256, &dwKeySpec)) 
		{
			
			if (AskUsername(szUserName, szComputerName))
			{
				if (AskPin(szPin))
				{
					CStoredCredentialManager* manager = CStoredCredentialManager::Instance();
					if (manager->CreateCredential(GetRidFromUsername(szUserName), Context,szPin,0, fCrypt))
					{
						MessageBox(hMainWnd,_T("Success"),_T("Success"),0);
					}
					else
					{
						MessageBoxWin32(GetLastError());
					}
				}
			}
			CertFreeCertificateContext(Context);
		}
	}
}

void menu_CREDMGMT_UpdateStoredCredential()
{
	WCHAR szPassword[256];
	WCHAR szUserName[256];
	WCHAR szComputerName[256];
	if (AskUsername(szUserName, szComputerName))
	{
		if (AskPin(szPassword))
		{
			CStoredCredentialManager* manager = CStoredCredentialManager::Instance();
			if (manager->UpdateCredential(GetRidFromUsername(szUserName), szPassword, 0))
			{
				MessageBox(hMainWnd,_T("Success"),_T("Success"),0);
			}
			else
			{
				MessageBoxWin32(GetLastError());
			}
		}
	}
}

void menu_CREDMGMT_DeleteStoredCredential()
{
	WCHAR szUserName[256];
	WCHAR szComputerName[256];
	if (AskUsername(szUserName, szComputerName))
	{
		CStoredCredentialManager* manager = CStoredCredentialManager::Instance();
		if (manager->RemoveStoredCredential(GetRidFromUsername(szUserName)))
		{
			MessageBox(hMainWnd,_T("Success"),_T("Success"),0);
		}
		else
		{
			MessageBoxWin32(GetLastError());
		}
	}
}

void menu_CREDMGMT_RetrieveStoredCredential()
{
	WCHAR szUserName[256];
	WCHAR szComputerName[256];
	WCHAR szReader[256];
	WCHAR szCard[256];
	WCHAR szContainer[256];
	WCHAR szProvider[256];
	WCHAR szPin[256];
	DWORD dwKeySpec = 0;
	PCCERT_CONTEXT pCertContext;
	PWSTR szPassword;

	if (AskForCard(szReader,256,szCard,256)) {
		if (pCertContext = SelectCerts(szReader,szCard,szProvider, 256, szContainer,256, &dwKeySpec)) 
		{
			if (AskUsername(szUserName, szComputerName))
			{
				if (AskPin(szPin))
				{
					CStoredCredentialManager* manager = CStoredCredentialManager::Instance();
					if (manager->GetPassword(GetRidFromUsername(szUserName), pCertContext, szPin, &szPassword))
					{
						MessageBoxW(hMainWnd,szPassword,L"Success",0);
						EIDFree(szPassword);
					}
					else
					{
						MessageBoxWin32(GetLastError());
					}
				}
			}
		}
		CertFreeCertificateContext(pCertContext);
	}
}

