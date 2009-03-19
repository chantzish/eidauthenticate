
PCCERT_CONTEXT GetCertificateFromCspInfo(__in PEID_SMARTCARD_CSP_INFO pCspInfo);
LPTSTR GetUserNameFromCertificate(__in PCCERT_CONTEXT pCertContext);
BOOL IsTrustedCertificate(__in PCCERT_CONTEXT pCertContext, __in_opt PDWORD pdwError);
LPCTSTR GetTrustErrorText(DWORD Status);
