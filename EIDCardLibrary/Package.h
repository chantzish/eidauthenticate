
BOOL IsEIDPackageAvailable();

HRESULT LsaInitString(PSTRING pszDestinationString, PCSTR pszSourceString);

HRESULT EIDUnlockLogonInit(
    PWSTR pwzDomain,
    PWSTR pwzUsername,
    PWSTR pwzPin,
    CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus,
    EID_INTERACTIVE_UNLOCK_LOGON* pkiul
    );


//packages the credentials into the buffer that the system expects
HRESULT EIDUnlockLogonPack(
    const EID_INTERACTIVE_UNLOCK_LOGON& rkiulIn,
	const PEID_SMARTCARD_CSP_INFO pCspInfo,
    BYTE** prgb,
    DWORD* pcb
    );

//szAuthPackageValue must be freed by  LsaFreeMemory
HRESULT CallAuthPackage(LPCWSTR username ,LPWSTR * szAuthPackageValue, PULONG szAuthPackageLen);

VOID EIDDebugPrintEIDUnlockLogonStruct(UCHAR dwLevel, PEID_INTERACTIVE_UNLOCK_LOGON pUnlockLogon) ;

VOID RemapPointer(PEID_INTERACTIVE_UNLOCK_LOGON pUnlockLogon, PVOID ClientAuthenticationBase);

DWORD GetRidFromUsername(LPTSTR szUsername);
BOOL HasAccountOnCurrentComputer(PWSTR szUserName);
BOOL IsCurrentUser(PWSTR szUserName);
BOOL IsAdmin(PWSTR szUserName);

BOOL LsaEIDCreateStoredCredential(__in_opt PWSTR szUsername, __in PWSTR szPassword, __in PWSTR szProvider, 
								  __in PWSTR szContainer, __in DWORD dwKeySpec);

BOOL LsaEIDRemoveStoredCredential(__in_opt PWSTR szUsername);

BOOL LsaEIDHasStoredCredential(__in_opt PWSTR szUsername);

BOOL MatchUserOrIsAdmin(__in DWORD dwRid, __in PLUID LogonId);
