NTSTATUS CompletePrimaryCredential(__in PLSA_UNICODE_STRING AuthenticatingAuthority,
						__in PLSA_UNICODE_STRING AccountName,
						__in PSID UserSid,
						__in PLUID LogonId,
						__in PWSTR szPassword,
						__in PLSA_DISPATCH_TABLE FunctionTable,
						__out  PSECPKG_PRIMARY_CRED PrimaryCredentials);
