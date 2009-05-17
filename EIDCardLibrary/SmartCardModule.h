
typedef struct _MGSC_CONTEXT
{
    //
    // Internal context
    //

    PVOID                           pvContext;

} MGSC_CONTEXT, *PMGSC_CONTEXT;

DWORD MgScCardAcquireContext(
    __inout                     PMGSC_CONTEXT pMgSc,
    __in                        SCARDCONTEXT hSCardContext,
    __in                        SCARDHANDLE hSCardHandle,
    __in                        LPWSTR wszCardName,
    __in_bcount(cbAtr)          PBYTE pbAtr,
    __in                        DWORD cbAtr,
    __in                        DWORD dwFlags);

void
MgScCardDeleteContext(
    __inout                     PMGSC_CONTEXT pMgSc);

DWORD 
MgScCardAuthenticatePin(
    __in                        PMGSC_CONTEXT pMgSc,
    __in                        LPWSTR      pwszUserId,
	__in                        LPWSTR      pwszPin,
    __out_opt                   PDWORD      pcAttemptsRemaining);
