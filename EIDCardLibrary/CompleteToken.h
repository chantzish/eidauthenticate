NTSTATUS GetTokenInformationv2(LPCWSTR wszMachine,LPCWSTR wszDomain, LPCWSTR wszUser,LSA_TOKEN_INFORMATION_V2** TokenInformation);

NTSTATUS UserNameToToken(__in_opt PLSA_UNICODE_STRING AuthenticatingAuthority,
						__in PLSA_UNICODE_STRING AccountName,
						__in PLSA_DISPATCH_TABLE FunctionTable,
						__out PLSA_TOKEN_INFORMATION_V2 *Token,
						__out LPDWORD TokenLength,
						__out PNTSTATUS SubStatus
						);
