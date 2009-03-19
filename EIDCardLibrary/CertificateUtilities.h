#pragma once

PCCERT_CONTEXT SelectFirstCertificateWithPrivateKey();
PCCERT_CONTEXT SelectCertificateWithPrivateKey(HWND hWnd = NULL);

BOOL AskForCard(LPWSTR szReader, DWORD ReaderLength,LPWSTR szCard,DWORD CardLength);

BOOL SchGetProviderNameFromCardName(__in LPCTSTR szCardName, __out LPTSTR szProviderName, __out PDWORD pdwProviderNameLen);

#define UI_CERTIFICATE_INFO_SAVEON_USERSTORE 0
#define UI_CERTIFICATE_INFO_SAVEON_SYSTEMSTORE 1
#define UI_CERTIFICATE_INFO_SAVEON_FILE 2
#define UI_CERTIFICATE_INFO_SAVEON_SMARTCARD 3

typedef struct _UI_CERTIFICATE_INFO
{
	LPTSTR szSubject;
	PCCERT_CONTEXT pRootCertificate;
	DWORD dwSaveon;
	LPTSTR szCard;
	LPTSTR szReader;
	DWORD dwKeyType;
	BOOL bIsSelfSigned;
	BOOL bHasSmartCardAuthentication;
	BOOL bHasServerAuthentication;
	BOOL bHasClientAuthentication;
	BOOL bHasEFS;
	BOOL bIsCA;
	SYSTEMTIME StartTime;
	SYSTEMTIME EndTime;
	// used to return new certificate context if needed
	// need to free it if returned
	BOOL fReturnCerticateContext;
	PCCERT_CONTEXT pNewCertificate;
} UI_CERTIFICATE_INFO, * PUI_CERTIFICATE_INFO;

PCCERT_CONTEXT GetCertificateWithPrivateKey();
BOOL CreateCertificate(PUI_CERTIFICATE_INFO CertificateInfo);
BOOL ClearCard(PTSTR szReaderName, PTSTR szCardName);
BOOL ImportFileToSmartCard(PTSTR szFileName, PTSTR szPassword, PTSTR szReaderName, PTSTR szCardname);