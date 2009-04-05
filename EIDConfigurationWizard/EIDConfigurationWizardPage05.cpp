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

class CContainerHolderTest : public IContainerHolderList
{
public:
	CContainerHolderTest(CContainer* pContainer)
	{
		_pContainer = pContainer;
	}

	virtual ~CContainerHolderTest()
	{
		if (_pContainer)
		{
			delete _pContainer;
		}
	}
	void Release()
	{
		delete this;
	}
	HRESULT SetUsageScenario(__in CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus,__in DWORD dwFlags){return S_OK;}
	CContainer* GetContainer()
	{
		return _pContainer;
	}
private:
	CContainer* _pContainer;
};



BOOL WizardFinishButton(PTSTR szPassword)
{
	BOOL fReturn = FALSE;
	SCARDCONTEXT     hSC;
	OPENCARDNAME_EX  dlgStruct;
	LONG             lReturn;
	DWORD			dwBestId;
	DWORD			dwLevel;
	DWORD dwError = 0;
	TCHAR szReader[1024];
	TCHAR szCard[1024];

	TCHAR szUserName[1024];
	DWORD dwSize = ARRAYSIZE(szUserName);
	GetUserName(szUserName, &dwSize);

	lReturn = SCardEstablishContext(SCARD_SCOPE_USER,
									NULL,
									NULL,
									&hSC );
	if ( SCARD_S_SUCCESS != lReturn )
	{
		return FALSE;
	}

	// Initialize the structure.
	memset(&dlgStruct, 0, sizeof(dlgStruct));
	dlgStruct.dwStructSize = sizeof(dlgStruct);
	dlgStruct.hSCardContext = hSC;
	dlgStruct.dwFlags = SC_DLG_MINIMAL_UI;
	dlgStruct.lpstrRdr = szReader;
	dlgStruct.nMaxRdr = ARRAYSIZE(szReader);
	dlgStruct.lpstrCard = szCard;
	dlgStruct.nMaxCard = ARRAYSIZE(szCard);
	dlgStruct.lpstrTitle = L"Select Card";
	dlgStruct.dwShareMode = 0;
	// Display the select card dialog box.
	lReturn = SCardUIDlgSelectCard(&dlgStruct);
	SCardReleaseContext(hSC);
	if ( SCARD_S_SUCCESS != lReturn )
	{
		return FALSE;
	}
	
	dwLevel = 0;
	dwBestId = 0;
	CContainerHolderFactory<CContainerHolderTest> MyCredentialList;
	MyCredentialList.ConnectNotification(szReader,szCard,0);
	if (MyCredentialList.HasContainerHolder())
	{
		DWORD dwMax = MyCredentialList.ContainerHolderCount();
		for (DWORD dwI = 0; dwI < dwMax ; dwI++)
		{
			CContainerHolderTest* MyTest = MyCredentialList.GetContainerHolderAt(dwI);
			if (_tcscmp(MyTest->GetContainer()->GetUserName(),szUserName)==0)
			{
				CContainer* container = MyTest->GetContainer();
				PCCERT_CONTEXT pCertContext = container->GetContainer();
				if (IsTrustedCertificate(pCertContext))
				{
					if (dwLevel == 0) 
					{
						dwLevel = 1;
						dwBestId = dwI;
					}
					if (CanEncryptPassword(NULL,0, pCertContext))
					{
						if (dwLevel == 1) 
						{
							dwLevel = 2;
							dwBestId = dwI;
						}
				
					}
				}
				else
				{
					dwError = GetLastError();
				}
				CertFreeCertificateContext(pCertContext);
			}
		}
	}
	// container found
	if (dwLevel)
	{
		CContainerHolderTest* MyTest = MyCredentialList.GetContainerHolderAt(dwBestId);
		CContainer* container = MyTest->GetContainer();
		fReturn = LsaEIDCreateStoredCredential(szUserName, szPassword, container->GetContainer());
		if (!fReturn)
		{
			dwError = GetLastError();
		}
	}
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

	credUiInfo.pszCaptionText = TEXT("Test");
	credUiInfo.pszMessageText = TEXT("");
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
		BYTE ProfileB[142];
		memcpy(ProfileB,Profile,ProfileLen);
		LsaDeregisterLogonProcess(hLsa);
		if (err)
		{
			MessageBoxWin32(LsaNtStatusToWinError(err));
		}
		else
		{
			MessageBox(hMainWnd,_T("Credential Valid"),_T("result"),0);
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
	CredUIConfirmCredentials(NULL,FALSE);
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



void SetEnabledLabel(HWND hwndDlg, int IDC, BOOL fEnabled)
{
	if (fEnabled)
	{
		SetWindowText(GetDlgItem(hwndDlg,IDC),TEXT("Enable"));
	}
	else
	{
		SetWindowText(GetDlgItem(hwndDlg,IDC),TEXT("Disable"));
	}
}

BOOL GetRequestedActivationStatus(HWND hwndDlg, int IDC)
{
	TCHAR szLabel[256];
	GetWindowText(GetDlgItem(hwndDlg,IDC),szLabel,ARRAYSIZE(szLabel));
	return _tcscmp(szLabel, TEXT("Enable")) == 0;
}


INT_PTR CALLBACK	WndProc_05PASSWORD(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam)
{
	int wmId;
	int wmEvent;
	TCHAR szPassword[1024];
	switch(message)
	{
	case WM_INITDIALOG:
		if (!IsElevated())
		{
			Button_SetElevationRequiredState(GetDlgItem(hWnd,IDC_05ForcePolicy),TRUE);
			Button_SetElevationRequiredState(GetDlgItem(hWnd,IDC_05RemovePolicy),TRUE);
		}
		break;
	case WM_COMMAND:
		wmId    = LOWORD(wParam);
		wmEvent = HIWORD(wParam);
		// Analyse les sélections de menu :
		switch (wmId)
		{	
			case IDC_05RemovePolicy:
				if (IsElevated())
				{
					ChangeRemovePolicy(GetRequestedActivationStatus(hWnd,IDC_05RemovePolicy));
				}
				else
				{
					// elevate
					SHELLEXECUTEINFO shExecInfo;
					TCHAR szName[1024];
					GetModuleFileName(GetModuleHandle(NULL),szName, ARRAYSIZE(szName));
					shExecInfo.cbSize = sizeof(SHELLEXECUTEINFO);

					shExecInfo.fMask = SEE_MASK_NOCLOSEPROCESS;
					shExecInfo.hwnd = NULL;
					shExecInfo.lpVerb = TEXT("runas");
					shExecInfo.lpFile = szName;
					if (GetRequestedActivationStatus(hWnd,IDC_05RemovePolicy))
					{
						shExecInfo.lpParameters = TEXT("ACTIVATEREMOVEPOLICY");
					}
					else
					{
						shExecInfo.lpParameters = TEXT("DESACTIVATEREMOVEPOLICY");
					}
					shExecInfo.lpDirectory = NULL;
					shExecInfo.nShow = SW_NORMAL;
					shExecInfo.hInstApp = NULL;

					if (!ShellExecuteEx(&shExecInfo))
					{
						MessageBoxWin32(GetLastError());
					}
					else
					{
						WaitForSingleObject(shExecInfo.hProcess, INFINITE);
					}
				}
				SetEnabledLabel(hWnd, IDC_05RemovePolicy, !IsRemovePolicyActive());
				break;
			case IDC_05ForcePolicy:
				if (IsElevated())
				{
					ChangeForceSmartCardLogonPolicy(GetRequestedActivationStatus(hWnd,IDC_05ForcePolicy));
				}
				else
				{
					// elevate
					SHELLEXECUTEINFO shExecInfo;
					TCHAR szName[1024];
					GetModuleFileName(GetModuleHandle(NULL),szName, ARRAYSIZE(szName));
					shExecInfo.cbSize = sizeof(SHELLEXECUTEINFO);

					shExecInfo.fMask = SEE_MASK_NOCLOSEPROCESS;
					shExecInfo.hwnd = NULL;
					shExecInfo.lpVerb = TEXT("runas");
					shExecInfo.lpFile = szName;
					if (GetRequestedActivationStatus(hWnd,IDC_05ForcePolicy))
					{
						shExecInfo.lpParameters = TEXT("ACTIVATEFORCEPOLICY");
					}
					else
					{
						shExecInfo.lpParameters = TEXT("DESACTIVATEFORCEPOLICY");
					}
					shExecInfo.lpDirectory = NULL;
					shExecInfo.nShow = SW_NORMAL;
					shExecInfo.hInstApp = NULL;

					if (!ShellExecuteEx(&shExecInfo))
					{
						MessageBoxWin32(GetLastError());
					}
					else
					{
						WaitForSingleObject(shExecInfo.hProcess, INFINITE);
					}
				}
				SetEnabledLabel(hWnd, IDC_05ForcePolicy, !IsForceSmartCardLogonPolicyActive());
				break;
		}
		break;
	case WM_NOTIFY :
        LPNMHDR pnmh = (LPNMHDR)lParam;
        switch(pnmh->code)
        {
			case PSN_SETACTIVE :
				//this is an interior page
				PropSheet_SetWizButtons(hWnd, PSWIZB_FINISH |	PSWIZB_BACK);
				SetEnabledLabel(hWnd, IDC_05RemovePolicy, !IsRemovePolicyActive());
				SetEnabledLabel(hWnd, IDC_05ForcePolicy,  !IsForceSmartCardLogonPolicyActive());
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
				break;
		}
    }
	return FALSE;
}