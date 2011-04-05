#include <windows.h>
#include <tchar.h>

#include "../EIDCardLibrary/Tracing.h"

#include "../EIDCardLibrary/CContainer.h"
#include "../EIDCardLibrary/CContainerHolderFactory.h"
#include "../EIDCardLibrary/StoredCredentialManagement.h"
#include "../EIDCardLibrary/Package.h"

#include "global.h"
#include "EIDConfigurationWizard.h"

#pragma comment(lib,"Credui")

#include "CContainerHolder.h"

// from previous step
// credentials
extern CContainerHolderFactory<CContainerHolderTest> *pCredentialList;
// selected credential
extern DWORD dwCurrentCredential;

extern BOOL PopulateListViewListData(HWND hWndListView);
extern BOOL InitListViewListIcon(HWND hWndListView);

extern BOOL fHasDeselected;

DWORD dwWizardError = 0;

BOOL WizardFinishButton(PTSTR szPassword)
{
	BOOL fReturn = FALSE;
	DWORD dwError = 0;
	
	CContainerHolderTest* MyTest = pCredentialList->GetContainerHolderAt(dwCurrentCredential);
	CContainer* container = MyTest->GetContainer();
	PCCERT_CONTEXT pCertContext = container->GetCertificate();
	fReturn = LsaEIDCreateStoredCredential(szUserName, szPassword, pCertContext, container->GetKeySpec() == AT_KEYEXCHANGE);
	if (!fReturn)
	{
		dwError = GetLastError();
	}
	CertFreeCertificateContext(pCertContext);
	SetLastError(dwError);
	return fReturn;
}

BOOL TestLogon(HWND hMainWnd)
{
	BOOL save = false;
	DWORD authPackage = 0;
	LPVOID authBuffer;
	ULONG authBufferSize = 0;
	CREDUI_INFO credUiInfo;
	BOOL fReturn = FALSE;
	DWORD dwError = 0;

	LSA_HANDLE hLsa;
	LSA_STRING Origin = { (USHORT)strlen("MYTEST"), (USHORT)sizeof("MYTEST"), "MYTEST" };
	QUOTA_LIMITS Quota = {0};
	TOKEN_SOURCE Source = { "TEST", { 0, 101 } };
	MSV1_0_INTERACTIVE_PROFILE *Profile;
	ULONG ProfileLen;
	LUID Luid;
	NTSTATUS err,stat;
	HANDLE Token;
	DWORD dwFlag = CREDUIWIN_AUTHPACKAGE_ONLY | CREDUIWIN_ENUMERATE_CURRENT_USER;
	RetrieveNegotiateAuthPackage(&authPackage);
	
	CoInitializeEx(NULL,COINIT_APARTMENTTHREADED); 
	TCHAR szTitle[256] = TEXT("");
	TCHAR szMessage[256] = TEXT("");
	TCHAR szCaption[256] = TEXT("");
	LoadString(g_hinst, IDS_05CREDINFOCAPTION, szCaption, ARRAYSIZE(szCaption));
	//LoadString(g_hinst, IDS_05CREDINFOMESSAGE, szMessage, ARRAYSIZE(szMessage));
	credUiInfo.pszCaptionText = szCaption;
	credUiInfo.pszMessageText = szMessage;
	credUiInfo.cbSize = sizeof(credUiInfo);
	credUiInfo.hbmBanner = NULL;
	credUiInfo.hwndParent = hMainWnd;

	DWORD result = CredUIPromptForWindowsCredentials(&(credUiInfo), 0, &(authPackage), 
    NULL, 0, &authBuffer, &authBufferSize, &(save), dwFlag);
	if (result == ERROR_SUCCESS)
	{
		err = LsaConnectUntrusted(&hLsa);
		/* Find the setuid package and call it */
		err = LsaLogonUser(hLsa, &Origin, (SECURITY_LOGON_TYPE)  Interactive , authPackage, authBuffer,authBufferSize,NULL, &Source, (PVOID*)&Profile, &ProfileLen, &Luid, &Token, &Quota, &stat);
		DWORD dwSize = sizeof(MSV1_0_INTERACTIVE_PROFILE);
		LsaDeregisterLogonProcess(hLsa);
		if (err)
		{
			dwError = LsaNtStatusToWinError(err);
		}
		else
		{
			/*LoadString(g_hinst, IDS_05CREDINFOCONFIRMTITLE, szTitle, ARRAYSIZE(szTitle));
			LoadString(g_hinst, IDS_05CREDINFOCONFIRMMESSAGE, szMessage, ARRAYSIZE(szMessage));
			MessageBox(hMainWnd,szMessage,szTitle,0);*/
			fReturn = TRUE;
			
			LsaFreeReturnBuffer(Profile);
			CloseHandle(Token);
			
		}
		CoTaskMemFree(authBuffer);
	}
	else //if (result == ERROR_CANCELLED)
	{
		//fReturn = TRUE;
		dwError = result;
	}
	//else
	//{
	//	//MessageBoxWin32(GetLastError());
	//}
	//CredUIConfirmCredentials(NULL,FALSE);
	SetLastError(dwError);
	return fReturn;
}


#define WM_MYMESSAGE WM_USER + 10
INT_PTR CALLBACK	WndProc_05PASSWORD(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam)
{
	int wmId;
	int wmEvent;
	TCHAR szPassword[1024];
	switch(message)
	{
	case WM_INITDIALOG:
		InitListViewListIcon(GetDlgItem(hWnd,IDC_05LIST));
		SendMessage(GetDlgItem(hWnd,IDC_05TEST), BM_SETCHECK, BST_CHECKED,0);
		break;
	case WM_MYMESSAGE:
		if (fHasDeselected)
		{
			ListView_SetItemState(GetDlgItem(hWnd,IDC_05LIST), dwCurrentCredential, LVIS_SELECTED | LVIS_FOCUSED, LVIS_SELECTED | LVIS_FOCUSED);
			ListView_Update(GetDlgItem(hWnd,IDC_05LIST), dwCurrentCredential);
		}
		return TRUE;
		break;
	case WM_COMMAND:
		wmId    = LOWORD(wParam);
		wmEvent = HIWORD(wParam);
		switch(wmId)
		{
		case IDC_05TEST:
			if (IsDlgButtonChecked(hWnd,IDC_05TEST))
			{
				PropSheet_SetWizButtons(hWnd, PSWIZB_NEXT |	PSWIZB_BACK);
			}
			else
			{
				PropSheet_SetWizButtons(hWnd, PSWIZB_FINISH | PSWIZB_BACK);
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
				ListView_DeleteAllItems(GetDlgItem(hWnd, IDC_05LIST));
				PopulateListViewListData(GetDlgItem(hWnd, IDC_05LIST));	
				//if (pCredentialList->GetContainerHolderAt(dwCurrentCredential)->GetIconIndex())
				//{
					PropSheet_SetWizButtons(hWnd, PSWIZB_NEXT |	PSWIZB_BACK);
				//}
				//else
				//{
				//	PropSheet_SetWizButtons(hWnd, PSWIZB_BACK);
				//}
				// load string from ressource
				break;
			case PSN_WIZFINISH :
			case PSN_WIZNEXT:
				GetWindowText(GetDlgItem(hWnd,IDC_05PASSWORD),szPassword,ARRAYSIZE(szPassword));
				if (!WizardFinishButton(szPassword))
				{
					MessageBoxWin32(GetLastError());
					SetWindowLongPtr(hWnd,DWLP_MSGRESULT,-1);
					return TRUE;
				}
				if (IsDlgButtonChecked(hWnd,IDC_05TEST))
				{
					if (!TestLogon(hWnd))
					{
						// handle if the credential test is cancelled
						dwWizardError = GetLastError();
						if (dwWizardError == ERROR_CANCELLED)
						{
							SetWindowLongPtr(hWnd,DWLP_MSGRESULT,-1);
							return TRUE;
						}
						// go to the error page
						SetWindowLongPtr(hWnd,DWLP_MSGRESULT,-1);
						PropSheet_SetCurSel(hWnd, NULL,6);
						return TRUE;
					}
					// go by default to the success page
				}
				break;
			case PSN_RESET:
				if (pCredentialList)
				{
					delete pCredentialList;
					pCredentialList = NULL;
				}
				break;

			case LVN_ITEMCHANGED:
				if (pnmh->idFrom == IDC_05LIST && pCredentialList)
				{
					if (((LPNMITEMACTIVATE)lParam)->uNewState & LVIS_SELECTED )
					{
						if ((DWORD)(((LPNMITEMACTIVATE)lParam)->iItem) < pCredentialList->ContainerHolderCount())
						{
							fHasDeselected = FALSE;
							dwCurrentCredential = ((LPNMITEMACTIVATE)lParam)->iItem;
							if (pCredentialList->GetContainerHolderAt(dwCurrentCredential)->GetIconIndex())
							{
								PropSheet_SetWizButtons(hWnd, PSWIZB_FINISH |	PSWIZB_BACK);
							}
							else
							{
								PropSheet_SetWizButtons(hWnd, PSWIZB_BACK);
							}
						}
					}
					else
					{
						fHasDeselected = TRUE;
						PropSheet_SetWizButtons(hWnd, PSWIZB_BACK);
						PostMessage(hWnd, WM_MYMESSAGE, 0, 0);
					}
				}
				break;
			case NM_DBLCLK:
				if (pnmh->idFrom == IDC_05LIST && pCredentialList)
				{
					if (((LPNMITEMACTIVATE)lParam)->iItem >= 0 && (DWORD)((LPNMITEMACTIVATE)lParam)->iItem < pCredentialList->ContainerHolderCount())
					{
						pCredentialList->GetContainerHolderAt(((LPNMITEMACTIVATE)lParam)->iItem)->GetContainer()->ViewCertificate(hWnd);
					}
				}
				break;
			
		}

    }
	return FALSE;
}