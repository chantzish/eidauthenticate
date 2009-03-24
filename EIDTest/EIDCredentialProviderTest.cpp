#include "stdafx.h"

#include <ntstatus.h>
#define WIN32_NO_STATUS
#include <windows.h>
#include <WinCred.h>
#include <tchar.h>
#include <credentialprovider.h>

#include "../EIDCardLibrary/EIDCardLibrary.h"
#include "../EIDCardLibrary/Tracing.h"
#include "../EIDCardLibrary/guid.h"

#pragma comment(lib,"Credui")
extern HWND hMainWnd;

void Menu_CREDENTIALUID_GENERIC(DWORD dwFlag)
{
  BOOL save = false;
  DWORD authPackage = 0;
  LPVOID authBuffer;
  ULONG authBufferSize = 0;
  CREDUI_INFO credUiInfo;
  
  LSA_HANDLE hLsa;
  LSA_STRING Origin = { (USHORT)strlen("MYTEST"), (USHORT)sizeof("MYTEST"), "MYTEST" };
  QUOTA_LIMITS Quota = {0};
  TOKEN_SOURCE Source = { "TEST", { 0, 101 } };
  MSV1_0_INTERACTIVE_PROFILE *Profile;
	ULONG ProfileLen;
	LUID Luid;
	NTSTATUS err,stat;
	HANDLE Token;

	CoInitializeEx(NULL,COINIT_APARTMENTTHREADED); 

  credUiInfo.pszCaptionText = TEXT("My caption");
  credUiInfo.pszMessageText = TEXT("My message");
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
			
			LsaFreeReturnBuffer(Profile);
			CloseHandle(Token);
			
		}
		CoTaskMemFree(authBuffer);
	}
	else if (result == ERROR_CANCELLED)
	{

	}
	else
	{
		result = CredUIConfirmCredentials(NULL,FALSE);
		MessageBoxWin32(GetLastError());
	}
	result = CredUIConfirmCredentials(NULL,FALSE);
//GetLastError();

}

void Menu_CREDENTIALUID()
{
	Menu_CREDENTIALUID_GENERIC(0);
}

void Menu_CREDENTIALUID_ADMIN()
{
	Menu_CREDENTIALUID_GENERIC(CREDUIWIN_ENUMERATE_ADMINS);
}

void menu_CRED_COM()
{
	ICredentialProvider* m_pIMyCredentialProvider = NULL;
	DWORD dwCount;
	DWORD dwCountDefault;
	BOOL bAutoLogon;
	ICredentialProviderCredential* m_pMyID = NULL;
	PWSTR pwszOptionalStatusText;
	CREDENTIAL_PROVIDER_STATUS_ICON cpsiOptionalStatusIcon;
	CoInitializeEx(NULL,COINIT_APARTMENTTHREADED); 
	CoCreateInstance(CLSID_CEIDProvider,NULL,CLSCTX_INPROC_SERVER,IID_ICredentialProvider,(void**)&m_pIMyCredentialProvider);
	//CoCreateInstance(CLSID_SmartcardCredentialProvider,NULL,CLSCTX_INPROC_SERVER,IID_ICredentialProvider,(void**)&m_pIMyCredentialProvider);
	m_pIMyCredentialProvider->SetUsageScenario(CPUS_CREDUI,0);
	Sleep(1000);
	m_pIMyCredentialProvider->GetCredentialCount(&dwCount,&dwCountDefault,&bAutoLogon);
	m_pIMyCredentialProvider->GetCredentialAt(0,&m_pMyID);
	m_pMyID->ReportResult(STATUS_ACCOUNT_RESTRICTION,STATUS_SUCCESS,&pwszOptionalStatusText,&cpsiOptionalStatusIcon);
	Sleep(1000);
	m_pMyID->Release();
	m_pIMyCredentialProvider->Release();
}
