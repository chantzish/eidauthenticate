#include <windows.h>
#include <tchar.h>

#include "../EIDCardLibrary/Tracing.h"
#include "../EIDCardLibrary/GPO.h"
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
	LoadString(g_hinst, IDS_05CREDINFOMESSAGE, szMessage, ARRAYSIZE(szMessage));
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
			MessageBoxWin32(LsaNtStatusToWinError(err));
		}
		else
		{
			LoadString(g_hinst, IDS_05CREDINFOCONFIRMTITLE, szTitle, ARRAYSIZE(szTitle));
			LoadString(g_hinst, IDS_05CREDINFOCONFIRMMESSAGE, szMessage, ARRAYSIZE(szMessage));
			MessageBox(hMainWnd,szMessage,szTitle,0);
			fReturn = TRUE;
			
			LsaFreeReturnBuffer(Profile);
			CloseHandle(Token);
			
		}
		CoTaskMemFree(authBuffer);
	}
	else if (result == ERROR_CANCELLED)
	{
		fReturn = TRUE;
	}
	else
	{
		MessageBoxWin32(GetLastError());
	}
	//CredUIConfirmCredentials(NULL,FALSE);
	return fReturn;
}

BOOL IsRemovePolicyActive()
{
	HKEY key;
	
	TCHAR szValue[2]=TEXT("0");
	DWORD size = sizeof(szValue);
	DWORD type=REG_SZ;	
	DWORD dwValue = 0;
	if (RegOpenKeyEx(HKEY_LOCAL_MACHINE,
		TEXT("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon"),
		NULL, KEY_READ, &key)==ERROR_SUCCESS){
		if (RegQueryValueEx(key,TEXT("scremoveoption"),NULL, &type,(LPBYTE) szValue, &size)==ERROR_SUCCESS)
		{
			dwValue = _tstoi(szValue);
		}
		RegCloseKey(key);
	}
	// remove policy active
	if (dwValue)
	{
		return TRUE;
	}
	else
	{
		return FALSE;
	}
}

BOOL IsForceSmartCardLogonPolicyActive()
{
	return GetPolicyValue(scforceoption) > 0;
}

#define WM_MYMESSAGE WM_USER + 10
INT_PTR CALLBACK	WndProc_05PASSWORD(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam)
{
	TCHAR szPassword[1024];
	switch(message)
	{
	case WM_INITDIALOG:
		if (!IsElevated())
		{
			// Set shield icon
			HICON ShieldIcon;
			SHSTOCKICONINFO sii = {0}; 
			sii.cbSize = sizeof(sii);
			SHGetStockIconInfo(SIID_SHIELD, SHGFI_ICON | SHGFI_SMALLICON, &sii);
			ShieldIcon = sii.hIcon;
			SendMessage(GetDlgItem(hWnd,IDC_05FORCEPOLICYICON),STM_SETICON ,(WPARAM)ShieldIcon,0);
			SendMessage(GetDlgItem(hWnd,IDC_05REMOVEPOLICYICON),STM_SETICON ,(WPARAM)ShieldIcon,0);
		}
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
	case WM_NOTIFY :
        LPNMHDR pnmh = (LPNMHDR)lParam;
        switch(pnmh->code)
        {
			case PSN_SETACTIVE :
				//this is an interior page
				ListView_DeleteAllItems(GetDlgItem(hWnd, IDC_05LIST));
				PopulateListViewListData(GetDlgItem(hWnd, IDC_05LIST));	
				if (pCredentialList->GetContainerHolderAt(dwCurrentCredential)->GetIconIndex())
				{
					PropSheet_SetWizButtons(hWnd, PSWIZB_FINISH |	PSWIZB_BACK);
				}
				else
				{
					PropSheet_SetWizButtons(hWnd, PSWIZB_BACK);
				}
				// load string from ressource
				{
					TCHAR szMessage[256] = TEXT("");
					if (IsRemovePolicyActive())
					{
						LoadString(g_hinst, IDS_05DESACTIVATEREMOVE, szMessage, ARRAYSIZE(szMessage));
					}
					else
					{
						LoadString(g_hinst, IDS_05ACTIVATEREMOVE, szMessage, ARRAYSIZE(szMessage));
					}
					SetWindowText(GetDlgItem(hWnd,IDC_05REMOVEPOLICYLINK),szMessage);
					if (IsForceSmartCardLogonPolicyActive())
					{
						LoadString(g_hinst, IDS_05DESACTIVATEFORCE, szMessage, ARRAYSIZE(szMessage));
					}
					else
					{
						LoadString(g_hinst, IDS_05ACTIVATEFORCE, szMessage, ARRAYSIZE(szMessage));
					}
					SetWindowText(GetDlgItem(hWnd,IDC_05FORCEPOLICYLINK),szMessage);
				}
				break;
			case PSN_WIZFINISH :
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
						SetWindowLongPtr(hWnd,DWLP_MSGRESULT,-1);
						return TRUE;
					}
				}
				if (pCredentialList)
				{
					delete pCredentialList;
					pCredentialList = NULL;
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
			case NM_CLICK:
			case NM_RETURN:
				{
					// enable / disable policy
					PNMLINK pNMLink = (PNMLINK)lParam;
					TCHAR szMessage[256] = TEXT("");
					LITEM item = pNMLink->item;
					if (wcscmp(item.szID, L"idActRemove") == 0)
					{
						if (!ChangeRemovePolicy(TRUE))
						{
							MessageBoxWin32(GetLastError());
						}
						else
						{
							LoadString(g_hinst, IDS_05DESACTIVATEREMOVE, szMessage, ARRAYSIZE(szMessage));
							SetWindowText(GetDlgItem(hWnd,IDC_05REMOVEPOLICYLINK),szMessage);
						}
					}
					else if (wcscmp(item.szID, L"idDesActRemove") == 0)
					{
						if (!ChangeRemovePolicy(FALSE))
						{
							MessageBoxWin32(GetLastError());
						}
						else
						{
							LoadString(g_hinst, IDS_05ACTIVATEREMOVE, szMessage, ARRAYSIZE(szMessage));
							SetWindowText(GetDlgItem(hWnd,IDC_05REMOVEPOLICYLINK),szMessage);
						}
					}
					else if (wcscmp(item.szID, L"idActForce") == 0)
					{
						if (!ChangeForceSmartCardLogonPolicy(TRUE))
						{
							MessageBoxWin32(GetLastError());
						}
						else
						{
							LoadString(g_hinst, IDS_05DESACTIVATEFORCE, szMessage, ARRAYSIZE(szMessage));
							SetWindowText(GetDlgItem(hWnd,IDC_05FORCEPOLICYLINK),szMessage);
						}
					}
					else if (wcscmp(item.szID, L"idDesActForce") == 0)
					{
						if (!ChangeForceSmartCardLogonPolicy(FALSE))
						{
							MessageBoxWin32(GetLastError());
						}
						else
						{
							LoadString(g_hinst, IDS_05ACTIVATEFORCE, szMessage, ARRAYSIZE(szMessage));
							SetWindowText(GetDlgItem(hWnd,IDC_05FORCEPOLICYLINK),szMessage);
						}
					}
				}
		}

    }
	return FALSE;
}