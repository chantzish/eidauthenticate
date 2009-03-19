

#define _TBEIDCardName TEXT("Belgium Electronic ID card")
#define WBEIDCardName L"Belgium Electronic ID card"
#define WBEIDCSP L"Belgium Identity Card CSP"
#define TBEIDCSP TEXT("Belgium Identity Card CSP")


BOOL GetBEIDCertificateData(__in LPCTSTR szReaderName,__out LPTSTR *pszContainerName,
							__out PDWORD pdwKeySpec, __out PBYTE *ppbData, __out PDWORD pdwCount,
							__in_opt DWORD dwKeySpec = 0);
PCCERT_CONTEXT GetBEIDCertificateFromCspInfo(__in PEID_SMARTCARD_CSP_INFO pCspInfo);
BOOL SolveBEIDChallenge(__in PCCERT_CONTEXT pCertContext, __in LPCTSTR Pin);