// EIDConfigurationWizardXP.cpp : définit le point d'entrée pour l'application.
//

#include "stdafx.h"
#include "EIDConfigurationWizardXP.h"
#include "resource.h"
#include "../EIDCardLibrary/EIDCardLibrary.h"
#include "../EIDCardLibrary/GPO.h"
#include "../EIDCardLibrary/Tracing.h"
#include "../EIDCardLibrary/CContainer.h"
#include "../EIDCardLibrary/CContainerHolderFactory.h"
#include "CContainerHolder.h"
#include "../EIDCardLibrary/CSmartCardNotifier.h"
#include "../EIDCardLibrary/XPCompatibility.h"

#pragma comment(lib,"Winscard")

// Variables globales :
HINSTANCE hInst;								// instance actuelle

class CWizard : ISmartCardConnectionNotifierRef
{
private:
	CContainerHolderFactory<CContainerHolderTest>* pCredentialList;
	CSmartCardConnectionNotifier* _pSmartCardConnectionNotifier;
	HINSTANCE _hInstance;
	HWND _hWnd;

public:
	CWizard(HINSTANCE hInstance)
	{
		pCredentialList = new CContainerHolderFactory<CContainerHolderTest>;
		pCredentialList->SetUsageScenario(CPUS_INVALID,0);
		_pSmartCardConnectionNotifier = new CSmartCardConnectionNotifier(this);
		_hInstance = hInstance;
	}

	void Show()
	{
		DialogBoxParam(_hInstance,MAKEINTRESOURCE(IDD_WIZARD),NULL,WndProc,reinterpret_cast<LPARAM>(this));
	}
	// static to member function
	static INT_PTR CALLBACK WndProc(HWND hwnd,UINT uMsg,WPARAM wp,LPARAM lp)
	{
		CWizard *pDlg=reinterpret_cast<CWizard*>(GetWindowLongPtr(hwnd,GWLP_USERDATA));
		if (!pDlg)
		{
			if (uMsg == WM_INITDIALOG)
			{
				pDlg = reinterpret_cast<CWizard*>(lp);
				pDlg->_hWnd = hwnd;
				SetWindowLongPtr(hwnd,GWLP_USERDATA,lp);
			}
			else
			{
				return 0; //let system deal with message
			}
		}
		//forward message to member function handler
		return pDlg->WndProc(uMsg,wp,lp);
	}
	INT_PTR CALLBACK WndProc(UINT message, WPARAM wParam, LPARAM lParam)
	{
		UNREFERENCED_PARAMETER(lParam);
		int index;
		switch (message)
		{
		case WM_INITDIALOG:
			if (LsaEIDHasStoredCredential(NULL))
			{
				EnableWindow(GetDlgItem(_hWnd,IDC_DELETE),TRUE);
			}
			else
			{
				EnableWindow(GetDlgItem(_hWnd,IDC_DELETE),FALSE);
			}
			SendMessage(GetDlgItem(_hWnd,IDC_CERTIFICATE),CB_RESETCONTENT,0,0);
			EnableWindow(GetDlgItem(_hWnd,IDC_CERTIFICATE),FALSE);
			EnableWindow(GetDlgItem(_hWnd,IDC_PASSWORD),FALSE);
			EnableWindow(GetDlgItem(_hWnd,IDC_SHOW),FALSE);
			EnableWindow(GetDlgItem(_hWnd,IDC_SET),FALSE);
			return (INT_PTR)TRUE;

		case WM_COMMAND:
			switch (LOWORD(wParam))
			{
					case IDOK:
					case IDCANCEL:
					{
						EndDialog(_hWnd, LOWORD(wParam));
						return (INT_PTR)TRUE;
					}
					break;
					case IDC_DELETE:
						if (IDYES == MessageBox(NULL,L"Would you like to remove the smart card registered ?",L"",MB_YESNO|MB_DEFBUTTON2))
						{
							if (!LsaEIDRemoveStoredCredential(NULL))
							{
								MessageBoxWin32Ex(GetLastError(),NULL);
							}
						}
						break;
					case IDC_SHOW:
						index = SendMessage(GetDlgItem(_hWnd,IDC_CERTIFICATE),CB_GETCURSEL,0,0);
						pCredentialList->GetContainerHolderAt(index)->GetContainer()->ViewCertificate();
						break;
					case IDC_SET:
						{
							// register the package again
							DebugBreak();
							index = SendMessage(GetDlgItem(_hWnd,IDC_CERTIFICATE),CB_GETCURSEL,0,0);
							CContainer* container = pCredentialList->GetContainerHolderAt(index)->GetContainer();
							PCCERT_CONTEXT pCertContext = container->GetCertificate();
							TCHAR szPassword[255];
							GetWindowText(GetDlgItem(_hWnd,IDC_PASSWORD),szPassword,ARRAYSIZE(szPassword));
							BOOL fSuccess = LsaEIDCreateStoredCredential(NULL, szPassword, pCertContext, container->GetKeySpec() == AT_KEYEXCHANGE);
							if (!fSuccess)
							{
								DWORD dwError = GetLastError();
								MessageBoxWin32(dwError);
							}
							else
							{
								MessageBoxWin32(0);
							}
							if (LsaEIDHasStoredCredential(NULL))
							{
								EnableWindow(GetDlgItem(_hWnd,IDC_DELETE),TRUE);
							}
							else
							{
								EnableWindow(GetDlgItem(_hWnd,IDC_DELETE),FALSE);
							}
						}
						break;

			}
		}
		return (INT_PTR)FALSE;
	}

	void Callback(EID_CREDENTIAL_PROVIDER_READER_STATE Message, __in LPCTSTR szReader,__in_opt LPCTSTR szCardName, __in_opt USHORT ActivityCount) 
	{
		switch(Message)
		{
		case EIDCPRSConnecting:
			pCredentialList->ConnectNotification(szReader,szCardName,ActivityCount);
			SendMessage(GetDlgItem(_hWnd,IDC_CERTIFICATE),CB_RESETCONTENT,0,0);
			if (pCredentialList->HasContainerHolder())
			{
				for (DWORD i = 0; i< pCredentialList->ContainerHolderCount(); i++)
				{
					SendMessage(GetDlgItem(_hWnd,IDC_CERTIFICATE),CB_INSERTSTRING,i,(LPARAM) pCredentialList->GetContainerHolderAt(i)->GetContainer()->GetContainerName());
				}
				EnableWindow(GetDlgItem(_hWnd,IDC_SHOW),TRUE);
				EnableWindow(GetDlgItem(_hWnd,IDC_SET),TRUE);
				EnableWindow(GetDlgItem(_hWnd,IDC_CERTIFICATE),TRUE);
				EnableWindow(GetDlgItem(_hWnd,IDC_PASSWORD),TRUE);
				SendMessage(GetDlgItem(_hWnd,IDC_CERTIFICATE),CB_SETCURSEL,0,0);
			}
			break;
		case EIDCPRSDisconnected:
			pCredentialList->DisconnectNotification(szReader);
			SendMessage(GetDlgItem(_hWnd,IDC_CERTIFICATE),CB_RESETCONTENT,0,0);
			EnableWindow(GetDlgItem(_hWnd,IDC_SHOW),FALSE);
			EnableWindow(GetDlgItem(_hWnd,IDC_SET),FALSE);
			EnableWindow(GetDlgItem(_hWnd,IDC_CERTIFICATE),FALSE);
			EnableWindow(GetDlgItem(_hWnd,IDC_PASSWORD),FALSE);
			break;
		}
	}
};

int APIENTRY _tWinMain(HINSTANCE hInstance,
                     HINSTANCE hPrevInstance,
                     LPTSTR    lpCmdLine,
                     int       nCmdShow)
{
	UNREFERENCED_PARAMETER(hPrevInstance);
	UNREFERENCED_PARAMETER(lpCmdLine);
	if (!IsEIDPackageAvailable())
	{
		MessageBox(NULL,TEXT("EIDAuthenticate is not installed"),TEXT("Error"),0);
		return 0;
	}
	CWizard wizard(hInstance);
	wizard.Show();
	
	return 0;
}