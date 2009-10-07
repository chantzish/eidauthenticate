#include <windows.h>
#include <tchar.h>
#include <Cryptuiapi.h>
#include <Sddl.h>
#include "EIDTestUIUtil.h"

#include "../EIDCardLibrary/EIDCardLibrary.h"
#include "../EIDCardLibrary/Tracing.h"
#include "../EIDCardLibrary/CertificateUtilities.h"

#pragma comment(lib,"Cryptui")

extern HINSTANCE hInst;
extern HWND hMainWnd;




void menu_UTIL_ListCertificates()
{
	WCHAR szReader[256];
	WCHAR szCard[256];
	WCHAR szContainer[256];
	WCHAR szProvider[256];
	PCCERT_CONTEXT Context = NULL;
	if (AskForCard(szReader,256,szCard,256))
	{
		Context = SelectCerts(szReader,szCard,szProvider,256,szContainer,256, NULL);
		if (Context) CertFreeCertificateContext(Context);
	}
}

void menu_UTIL_DeleteOneCertificate()
{
	WCHAR szReader[256];
	WCHAR szCard[256];
	WCHAR szContainer[256];
	WCHAR szProvider[256];
	HCRYPTPROV hProv;
	PCCERT_CONTEXT Context = NULL;
	if (AskForCard(szReader,256,szCard,256)) {
		if (Context = SelectCerts(szReader,szCard,szProvider, 256, szContainer,256, NULL)) 
		{
			CertFreeCertificateContext(Context);
			// Acquire a context on the current container
			if (CryptAcquireContext(&hProv,
					szContainer,
					szProvider,
					PROV_RSA_FULL,
					CRYPT_DELETEKEYSET))
			{
				WCHAR Buffer[4000];
				_stprintf_s(Buffer,4000,L"Container %s deleted",szContainer);
				MessageBox(NULL,Buffer,L"",0);
			}
		}
	}
}
void menu_UTIL_ClearCard()
{
	WCHAR szReaderName[256];
	WCHAR szCardName[256];

	if (AskForCard(szReaderName,256,szCardName,256))
	{
		if (IDOK == MessageBox(NULL,L"All data will be deleted !!!!!!!",L"",MB_OKCANCEL|MB_DEFBUTTON2))
		{
			ClearCard(szReaderName,szCardName);
			MessageBox(NULL,L"All data has been deleted !!!!!!!",L"",0);
		}
	}
}


DWORD SelectCertificateInfo(PUI_CERTIFICATE_INFO pCertificateInfo);
void FreeCertificateInfo(PUI_CERTIFICATE_INFO pCertificateInfo);

void menu_UTIL_CreateCert()
{
	UI_CERTIFICATE_INFO CertificateInfo = {0};
	WCHAR szCard[256];
	WCHAR szReader[256];
	BOOL bContinue = TRUE;
	// get input from user
	if (SelectCertificateInfo(&CertificateInfo)) 
	{
		
		if (CertificateInfo.dwSaveon == UI_CERTIFICATE_INFO_SAVEON_SMARTCARD)
		{
			if (!AskForCard(szReader, 256, szCard,256))
			{
				bContinue = FALSE;
			}
			else
			{
				CertificateInfo.szCard = szCard;
				CertificateInfo.szReader = szReader;
			}
		}
		if (bContinue)
		{
			if (CreateCertificate(&CertificateInfo))
			{
				MessageBox(hMainWnd,TEXT("Success"),TEXT("Success"),0);
			}
			else
			{
				MessageBoxWin32(GetLastError());
			}
		}
	}
	FreeCertificateInfo(&CertificateInfo);
}

void menu_UTIL_ShowSecurityDescriptor()
{
	PCCERT_CONTEXT pCertContext = SelectCertificateWithPrivateKey(hMainWnd);
	HCRYPTPROV hProv = NULL;
	DWORD dwKeyType;
	BOOL fCallerFreeProvOrNCryptKey;
	DWORD dwError = 0;
	PSECURITY_DESCRIPTOR pSD = NULL;
	DWORD dwSize = 0;
	PTSTR szSD = NULL;
	if (!pCertContext) return;
	__try
	{
		if (!CryptAcquireCertificatePrivateKey(pCertContext,0,NULL,
					&hProv,&dwKeyType,&fCallerFreeProvOrNCryptKey))
		{
			dwError = GetLastError();
			__leave;
		}
		if (!CryptGetProvParam(hProv,PP_KEYSET_SEC_DESCR,(BYTE*)pSD,&dwSize, 
			OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION))
		{
			dwError = GetLastError();
			__leave;
		}
		pSD = (PSECURITY_DESCRIPTOR) EIDAlloc(dwSize);
		if (!pSD)
		{
			dwError = GetLastError();
			__leave;
		}
		if (!CryptGetProvParam(hProv,PP_KEYSET_SEC_DESCR,(BYTE*)pSD,&dwSize, 
			OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION))
		{
			dwError = GetLastError();
			__leave;
		}
		if (!ConvertSecurityDescriptorToStringSecurityDescriptor(pSD, SDDL_REVISION_1, 
			OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION,&szSD,NULL))
		{
			dwError = GetLastError();
			__leave;
		}
		MessageBox(hMainWnd, szSD, TEXT("Security Descriptor"),0);
	}
	__finally
	{
		if (szSD)
			EIDFree(szSD);
		if (pSD)
			EIDFree(pSD);
		if (hProv)
			CryptReleaseContext(hProv, 0);
		if (pCertContext)
			CertFreeCertificateContext(pCertContext);
	}
	if (dwError)
		MessageBoxWin32(dwError);
}