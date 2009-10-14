#include "stdafx.h"

#include <ntstatus.h>
#define WIN32_NO_STATUS
#include <windows.h>
#include <WinCred.h>
#include <tchar.h>
#include <credentialprovider.h>
#define SECURITY_WIN32
#include <Security.h>
#include <sspi.h>

#include "../EIDCardLibrary/EIDCardLibrary.h"
#include "../EIDCardLibrary/Tracing.h"
#include "../EIDCardLibrary/guid.h"
#include "../EIDCardLibrary/package.h"

#include "EIDTestUIUtil.h"

#pragma comment(lib,"Credui")
extern HWND hMainWnd;

#include "EIDCredentialProviderTest.h"

AuthenticationType authenticationType;

void SetAuthentication(AuthenticationType type)
{
	authenticationType = type;
}

BOOL AuthenticateWithLsaLogonUser(LONG authPackage, PVOID authBuffer, DWORD authBufferSize)
{
	BOOL fReturn = FALSE;
	LSA_HANDLE hLsa;
	MSV1_0_INTERACTIVE_PROFILE *Profile;
	ULONG ProfileLen;
	LSA_STRING Origin = { (USHORT)strlen("MYTEST"), (USHORT)sizeof("MYTEST"), "MYTEST" };
	TOKEN_SOURCE Source = { "TEST", { 0, 101 } };
	QUOTA_LIMITS Quota = {0};
	LUID Luid;
	NTSTATUS err,stat;
	HANDLE Token;
	err = LsaConnectUntrusted(&hLsa);
	
	err = LsaLogonUser(hLsa, &Origin, (SECURITY_LOGON_TYPE)  Interactive , authPackage, authBuffer,authBufferSize,NULL, &Source, (PVOID*)&Profile, &ProfileLen, &Luid, &Token, &Quota, &stat);
	
	LsaDeregisterLogonProcess(hLsa);
	if (err)
	{
		SetLastError(LsaNtStatusToWinError(err));
	}
	else
	{
		fReturn = TRUE;
		LsaFreeReturnBuffer(Profile);
		CloseHandle(Token);
		
	}
	return fReturn;
}

BOOL AuthenticateWithSSPI(PTSTR szPrincipal, PTSTR szPassword, PTSTR szSSP)
{

	BOOL fReturn = FALSE;
	DWORD err;
	TCHAR szDomain[255] = TEXT("");
	SEC_WINNT_AUTH_IDENTITY_EX authIdent = {
        SEC_WINNT_AUTH_IDENTITY_VERSION,
        sizeof authIdent,
        (unsigned short *)szPrincipal,
		_tcsclen(szPrincipal),
        (unsigned short *)szDomain,
		_tcsclen(szDomain),
		(unsigned short *)szPassword,
		_tcsclen(szPassword),
#ifdef UNICODE
        SEC_WINNT_AUTH_IDENTITY_UNICODE
#else
		SEC_WINNT_AUTH_IDENTITY_ANSI
#endif
        ,0, 0
    };
	CtxtHandle hctxClient;
	CtxtHandle hctxServer;
	// create two buffers:
	//    one for the client sending tokens to the server,
	//    one for the server sending tokens to the client
	// (buffer size chosen based on current Kerb SSP setting
	//  for cbMaxToken - you may need to adjust this)
	BYTE bufC2S[8000];
	BYTE bufS2C[8000];
	SecBuffer sbufC2S = { sizeof bufC2S, SECBUFFER_TOKEN, bufC2S };
	SecBuffer sbufS2C = { sizeof bufS2C, SECBUFFER_TOKEN, bufS2C };
	SecBufferDesc bdC2S = { SECBUFFER_VERSION, 1, &sbufC2S };
	SecBufferDesc bdS2C = { SECBUFFER_VERSION, 1, &sbufS2C };

	// don't really need any special context attributes
	DWORD grfRequiredCtxAttrsClient = ISC_REQ_CONNECTION;
	DWORD grfRequiredCtxAttrsServer = ISC_REQ_CONNECTION;

	// set up some aliases to make it obvious what's happening
	PCtxtHandle    pClientCtxHandleIn  = 0;
	PCtxtHandle    pClientCtxHandleOut = &hctxClient;
	PCtxtHandle    pServerCtxHandleIn  = 0;
	PCtxtHandle    pServerCtxHandleOut = &hctxServer;
	SecBufferDesc* pClientInput  = 0;
	SecBufferDesc* pClientOutput = &bdC2S;
	SecBufferDesc* pServerInput  = &bdC2S;
	SecBufferDesc* pServerOutput = &bdS2C;
	DWORD          grfCtxAttrsClient = 0;
	DWORD          grfCtxAttrsServer = 0;
	TimeStamp      expiryClientCtx;
	TimeStamp      expiryServerCtx;
	bool bClientContinue = true;
	bool bServerContinue = true;
	CredHandle hcredClient;
	CredHandle hcredServer;
	TimeStamp expiryClient;
	TimeStamp expiryServer;

	__try
	{
		err = AcquireCredentialsHandle(NULL, szSSP, SECPKG_CRED_OUTBOUND | SECPKG_CRED_INBOUND,
											0, &authIdent, 0, 0,
											&hcredClient, &expiryClient);
		if (err != SEC_E_OK)
		{
			__leave;
		}
		/*AcquireCredentialsHandle(0, szSSP, SECPKG_CRED_INBOUND,
											  0, 0, 0, 0, &hcredServer,
											  &expiryServer);
		if (err != SEC_E_OK)
		{
			__leave;
		}*/

		// since the caller is acting as the server, we need
		// a server principal name so that the client will
		// be able to get a Kerb ticket (if Kerb is used)
		wchar_t szSPN[256];
		ULONG cchSPN = sizeof szSPN / sizeof *szSPN;
		GetUserNameEx(NameSamCompatible, szSPN, &cchSPN);

		// perform the authentication handshake, playing the
		// role of both client *and* server.
		while (bClientContinue || bServerContinue) {
			if (bClientContinue) {
				sbufC2S.cbBuffer = sizeof bufC2S;
				err = InitializeSecurityContext(
					&hcredClient, pClientCtxHandleIn,
					szSPN,
					grfRequiredCtxAttrsClient,
					0, SECURITY_NATIVE_DREP,
					pClientInput, 0,
					pClientCtxHandleOut,
					pClientOutput,
					&grfCtxAttrsClient,
					&expiryClientCtx);
				switch (err) {
					case 0:
						bClientContinue = false;
						break;
					case SEC_I_CONTINUE_NEEDED:
						pClientCtxHandleIn = pClientCtxHandleOut;
						pClientInput       = pServerOutput;
						break;
					default:
						__leave;
				}
			}

			if (bServerContinue) {
				sbufS2C.cbBuffer = sizeof bufS2C;
				err = AcceptSecurityContext(
					&hcredClient, pServerCtxHandleIn,
					pServerInput,
					grfRequiredCtxAttrsServer,
					SECURITY_NATIVE_DREP,
					pServerCtxHandleOut,
					pServerOutput,
					&grfCtxAttrsServer,
					&expiryServerCtx);
				switch (err) {
					case 0:
						bServerContinue = false;
						break;
					case SEC_I_CONTINUE_NEEDED:
						pServerCtxHandleIn = pServerCtxHandleOut;
						break;
					default:
						__leave;
				}
			}
		}

		// clean up
		FreeCredentialsHandle(&hcredClient);
		FreeCredentialsHandle(&hcredServer);
		DeleteSecurityContext(pServerCtxHandleOut);
		DeleteSecurityContext(pClientCtxHandleOut);
		fReturn = TRUE;
	}
	__finally
	{
	}
	SetLastError(err);
	return fReturn;
}

BOOL AuthenticateWithSSPIWrapper(LONG authPackage, PVOID authBuffer, DWORD authBufferSize)
{
	 
    TCHAR szSSP[255] = TEXT("Negotiate");
	SECURITY_STATUS err;
	DWORD dwNbPackage;
	PSecPkgInfo pPackageInfo;
	HANDLE hLsa;
	NTSTATUS status = LsaConnectUntrusted(&hLsa);
	if (status != STATUS_SUCCESS)
	{
		SetLastError(LsaNtStatusToWinError(status));
		return FALSE;
	}
	err = EnumerateSecurityPackages(&dwNbPackage, &pPackageInfo);
	if (err != SEC_E_OK)
	{
		SetLastError(err);
		return FALSE;
	}
	for(DWORD dwI = 0; dwI < dwNbPackage; dwI++)
	{
		ULONG ulAuthPackage;
        LSA_STRING lsaszPackageName;
		CHAR szTemp[255];
		WideCharToMultiByte(CP_ACP, 0, pPackageInfo[dwI].Name, _tcsclen(pPackageInfo[dwI].Name) +1,
				szTemp, ARRAYSIZE(szTemp), NULL, NULL);
		LsaInitString(&lsaszPackageName,szTemp );

        status = LsaLookupAuthenticationPackage(hLsa, &lsaszPackageName, &ulAuthPackage);
		if (status == STATUS_SUCCESS && ulAuthPackage == authPackage)
		{
			_tcscpy_s(szSSP, ARRAYSIZE(szSSP), pPackageInfo[dwI].Name);
			break;
		}
	}
	FreeContextBuffer(pPackageInfo);
	LsaDeregisterLogonProcess(hLsa);

	TCHAR szPrincipal[255] = TEXT("");
	DWORD dwPrincipalSize = ARRAYSIZE(szPrincipal);
	TCHAR szDomain[255] = TEXT("");
	DWORD dwDomainSize = ARRAYSIZE(szDomain);
	TCHAR szPassword[255] = TEXT("");
	DWORD dwPasswordSize = ARRAYSIZE(szPassword);
	if (!CredUnPackAuthenticationBuffer(0, authBuffer, authBufferSize, 
						szPrincipal, &dwPrincipalSize,
						szDomain, &dwDomainSize,
						szPassword, &dwPasswordSize))
	{
		
		return FALSE;
	}
	return AuthenticateWithSSPI(szPrincipal,szPassword, szSSP);
}
typedef struct _KERB_SMARTCARD_CSP_INFO {
  DWORD dwCspInfoLen;
  DWORD MessageType;
  union {
    PVOID ContextInformation;
    ULONG64 SpaceHolderForWow64;
  } ;
  DWORD flags;
  DWORD KeySpec;
  ULONG nCardNameOffset;
  ULONG nReaderNameOffset;
  ULONG nContainerNameOffset;
  ULONG nCSPNameOffset;
  TCHAR bBuffer;
}KERB_SMARTCARD_CSP_INFO, *PKERB_SMARTCARD_CSP_INFO;

void Menu_CREDENTIALUID_GENERIC(DWORD dwFlag)
{
	BOOL save = false;
	DWORD authPackage = 0;
	LPVOID authBuffer;
	ULONG authBufferSize = 0;
	CREDUI_INFO credUiInfo;

	if (dwFlag | CREDUIWIN_AUTHPACKAGE_ONLY)
	{
		RetrieveNegotiateAuthPackage(&authPackage);
	}

	CoInitializeEx(NULL,COINIT_APARTMENTTHREADED); 

	credUiInfo.pszCaptionText = TEXT("My caption");
	credUiInfo.pszMessageText = TEXT("My message");
	credUiInfo.cbSize = sizeof(credUiInfo);
	credUiInfo.hbmBanner = NULL;
	credUiInfo.hwndParent = hMainWnd;

	DWORD result = 0;
	result = CredUIPromptForWindowsCredentials(&(credUiInfo), 0, &(authPackage), 
		NULL, 0, &authBuffer, &authBufferSize, &(save), dwFlag);
	if (result == ERROR_SUCCESS)
	{
		//AuthenticateWithLsaLogonUser(authPackage,authBuffer,authBufferSize);
		if (AuthenticateWithSSPIWrapper(authPackage,authBuffer,authBufferSize))
		{
			MessageBox(hMainWnd,_T("Credential Valid"),_T("result"),0);
		}
		else
		{
			MessageBoxWin32(GetLastError());
		}
		CoTaskMemFree(authBuffer);
	}
	else if (result == ERROR_CANCELLED)
	{

	}
	else
	{
		MessageBoxWin32(result);
	}
	result = CredUIConfirmCredentials(NULL,FALSE);
}

void Menu_CREDENTIALUID()
{
	Menu_CREDENTIALUID_GENERIC(0);
}

void Menu_CREDENTIALUID_ADMIN()
{
	Menu_CREDENTIALUID_GENERIC(CREDUIWIN_ENUMERATE_ADMINS);
}

void Menu_CREDENTIALUID_ONLY_EID()
{
	Menu_CREDENTIALUID_GENERIC(CREDUIWIN_AUTHPACKAGE_ONLY);
}

void menu_CREDENTIALUID_OldBehavior()
{
	DWORD dwStatus;
	CREDUI_INFO credUiInfo;
	TCHAR szUsername[CREDUI_MAX_USERNAME_LENGTH+1] = TEXT("");
	TCHAR szPassword[CREDUI_MAX_PASSWORD_LENGTH+1] = TEXT("");
	credUiInfo.pszCaptionText = TEXT("My caption");
	credUiInfo.pszMessageText = TEXT("My message");
	credUiInfo.cbSize = sizeof(credUiInfo);
	credUiInfo.hbmBanner = NULL;
	credUiInfo.hwndParent = hMainWnd;
	dwStatus = CredUIPromptForCredentials(&credUiInfo, TEXT("test"), NULL, 0, 
		szUsername, CREDUI_MAX_USERNAME_LENGTH,
		szPassword, CREDUI_MAX_PASSWORD_LENGTH,
		FALSE, 0);
	if (dwStatus == NO_ERROR)
	{
		if (!AuthenticateWithSSPI(szUsername, szPassword,AUTHENTICATIONPACKAGENAMET))
		{
			MessageBoxWin32(GetLastError());
		}
		else
		{
			MessageBox(hMainWnd,_T("Credential Valid"),_T("result"),0);
		}
	}
	else if (dwStatus == ERROR_CANCELLED)
	{
	}
	else
	{
		MessageBoxWin32(dwStatus);
	}
	CredUIConfirmCredentials(NULL,FALSE);
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

typedef BOOL (NTAPI * PRShowRestoreFromMsginaW) (DWORD, DWORD, PWSTR, DWORD);
void menu_ResetPasswordWizard()
{
	WCHAR szUserName[256];
	WCHAR szComputerName[256];
	HMODULE keymgrDll = NULL;
	if (AskUsername(szUserName, szComputerName))
	{
		__try
		{
			keymgrDll = LoadLibrary(TEXT("keymgr.dll"));
			if (!keymgrDll)
			{
				__leave;
			}
			PRShowRestoreFromMsginaW MyPRShowRestoreFromMsginaW = (PRShowRestoreFromMsginaW) GetProcAddress(keymgrDll,"PRShowRestoreFromMsginaW");
			if (!MyPRShowRestoreFromMsginaW)
			{
				__leave;
			}
			MyPRShowRestoreFromMsginaW(NULL,NULL,szUserName,NULL);
		}
		__finally
		{
			if (keymgrDll)
				FreeLibrary(keymgrDll);
		}
	}
}