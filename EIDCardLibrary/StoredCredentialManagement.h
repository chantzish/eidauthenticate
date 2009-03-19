
BOOL CreateStoredCredential(__in DWORD dwRid,  __in PWSTR szPassword, __in_opt USHORT dwPasswordLen,
							__in PCWSTR szProvider, __in PCWSTR szContainer, __in DWORD dwKeySpec);


BOOL UpdateStoredCredential(__in DWORD dwRid, __in PWSTR szPassword, __in_opt USHORT usPasswordLen);
BOOL UpdateStoredCredentialEx(__in DWORD dwRid, __in PWSTR szPassword, __in_opt USHORT usPasswordLen,
							__in_opt PBYTE pPublicKeyBlob, __in_opt USHORT usPublicKeySize, __in_opt BOOL fEncryptPassword);


BOOL RetrieveStoredCredential(__in DWORD dwRid, __in PCCERT_CONTEXT pCertContext, __in LPCTSTR Pin, __out PWSTR *pszPassword);

BOOL RemoveStoredCredential(__in DWORD dwRid);
BOOL CanEncryptPassword(__in_opt HCRYPTPROV hProv, __in_opt DWORD dwKeySpec,  __in_opt PCCERT_CONTEXT pCertContext);

BOOL HasStoredCredential(__in DWORD dwRid);