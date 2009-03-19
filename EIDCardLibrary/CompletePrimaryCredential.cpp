#include <ntstatus.h>
#define WIN32_NO_STATUS
#include <windows.h>

#define SECURITY_WIN32
#include <sspi.h>

#include <Ntsecapi.h>
#include <NtSecPkg.h>
#include <SubAuth.h>
#include <lm.h>
#include <Sddl.h>
#include <wchar.h>
#include <WinCred.h>
#include "Tracing.h"
#include "StoredCredentialManagement.h"

NTSTATUS GetPasswordFromSam( __in PSID UserSid, __out unsigned char * Password);

NTSTATUS CompletePrimaryCredential(__in PLSA_UNICODE_STRING AuthenticatingAuthority,
						__in PLSA_UNICODE_STRING AccountName,
						__in PSID UserSid,
						__in PLUID LogonId,
						__in PWSTR szPassword,
						__in PLSA_DISPATCH_TABLE FunctionTable,
						__out  PSECPKG_PRIMARY_CRED PrimaryCredentials)
{

	EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Enter");
	memset(PrimaryCredentials, 0, sizeof(SECPKG_PRIMARY_CRED));
	PrimaryCredentials->LogonId.HighPart = LogonId->HighPart;
	PrimaryCredentials->LogonId.LowPart = LogonId->LowPart;

	PrimaryCredentials->DownlevelName.Length = AccountName->Length;
	PrimaryCredentials->DownlevelName.MaximumLength = AccountName->MaximumLength;
	PrimaryCredentials->DownlevelName.Buffer = (PWSTR) FunctionTable->AllocateLsaHeap(AccountName->MaximumLength);
	memcpy(PrimaryCredentials->DownlevelName.Buffer, AccountName->Buffer, AccountName->MaximumLength);

	PrimaryCredentials->DomainName.Length = AuthenticatingAuthority->Length;
	PrimaryCredentials->DomainName.MaximumLength = AuthenticatingAuthority->MaximumLength;
	PrimaryCredentials->DomainName.Buffer = (PWSTR) FunctionTable->AllocateLsaHeap(AuthenticatingAuthority->MaximumLength);
	if (PrimaryCredentials->DomainName.Buffer)
	{
		memcpy(PrimaryCredentials->DomainName.Buffer, AuthenticatingAuthority->Buffer, AuthenticatingAuthority->MaximumLength);
	}

	PrimaryCredentials->Password.Length = (USHORT) wcslen(szPassword) * sizeof(WCHAR);
	PrimaryCredentials->Password.MaximumLength = PrimaryCredentials->Password.Length;
	PrimaryCredentials->Password.Buffer = (PWSTR) FunctionTable->AllocateLsaHeap(PrimaryCredentials->Password.MaximumLength);
	if (PrimaryCredentials->Password.Buffer)
	{
		memcpy(PrimaryCredentials->Password.Buffer, szPassword, PrimaryCredentials->Password.Length);
		/*PrimaryCredentials->Password.Buffer[32] = 0;*/
		/*if (GetPasswordFromSam(UserSid,(PBYTE) PrimaryCredentials->Password.Buffer) != STATUS_SUCCESS)
		{
			PrimaryCredentials->Password.Length = 0;
		}*/
		/*WCHAR szTempPass[256]=L"EAA58923167D67D9AC370B98484A0058CA4D5A3B";
		PrimaryCredentials->Password.Length = wcslen(szTempPass) * sizeof(WCHAR);
		memcpy(PrimaryCredentials->Password.Buffer, szTempPass, PrimaryCredentials->Password.Length);*/
	}

	// we decide that the password cannot be changed so copy it into old pass
	PrimaryCredentials->OldPassword.Length = 0;
	PrimaryCredentials->OldPassword.MaximumLength = 0;
	PrimaryCredentials->OldPassword.Buffer = (PWSTR) FunctionTable->AllocateLsaHeap(PrimaryCredentials->OldPassword.MaximumLength);;

	PrimaryCredentials->Flags = PRIMARY_CRED_CLEAR_PASSWORD;

	PrimaryCredentials->UserSid = (PSID) FunctionTable->AllocateLsaHeap(GetLengthSid(UserSid));
	if (PrimaryCredentials->UserSid)
	{
		CopySid(GetLengthSid(UserSid),PrimaryCredentials->UserSid,UserSid);
	}

	PrimaryCredentials->DnsDomainName.Length = 0;
	PrimaryCredentials->DnsDomainName.MaximumLength = 0;
	PrimaryCredentials->DnsDomainName.Buffer = NULL;

	PrimaryCredentials->Upn.Length = 0;
	PrimaryCredentials->Upn.MaximumLength = 0;
	PrimaryCredentials->Upn.Buffer = NULL;

	PrimaryCredentials->LogonServer.Length = AuthenticatingAuthority->Length;
	PrimaryCredentials->LogonServer.MaximumLength = AuthenticatingAuthority->MaximumLength;
	PrimaryCredentials->LogonServer.Buffer = (PWSTR) FunctionTable->AllocateLsaHeap(AuthenticatingAuthority->MaximumLength);
	if (PrimaryCredentials->LogonServer.Buffer)
	{
		memcpy(PrimaryCredentials->LogonServer.Buffer, AuthenticatingAuthority->Buffer, AuthenticatingAuthority->MaximumLength);
	}
	EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Leave");
	return STATUS_SUCCESS;	
}

typedef struct _ENCRYPTED_LM_OWF_PASSWORD {
    unsigned char data[16];
} ENCRYPTED_LM_OWF_PASSWORD,
  *PENCRYPTED_LM_OWF_PASSWORD,
  ENCRYPTED_NT_OWF_PASSWORD,
  *PENCRYPTED_NT_OWF_PASSWORD;

typedef struct _SAMPR_USER_INTERNAL1_INFORMATION {
    ENCRYPTED_NT_OWF_PASSWORD  EncryptedNtOwfPassword;
    ENCRYPTED_LM_OWF_PASSWORD  EncryptedLmOwfPassword;
    unsigned char              NtPasswordPresent;
    unsigned char              LmPasswordPresent;
    unsigned char              PasswordExpired;
} SAMPR_USER_INTERNAL1_INFORMATION,
  *PSAMPR_USER_INTERNAL1_INFORMATION;

typedef enum _USER_INFORMATION_CLASS {
    UserInternal1Information = 18,
} USER_INFORMATION_CLASS, *PUSER_INFORMATION_CLASS;

typedef PSAMPR_USER_INTERNAL1_INFORMATION PSAMPR_USER_INFO_BUFFER;

typedef WCHAR * PSAMPR_SERVER_NAME;
typedef PVOID SAMPR_HANDLE;


// opnum 0
typedef NTSTATUS  (NTAPI *SamrConnect) (
    __in PSAMPR_SERVER_NAME ServerName,
    __out SAMPR_HANDLE * ServerHandle,
    __in DWORD DesiredAccess,
	__in DWORD
    );

// opnum 1
typedef NTSTATUS  (NTAPI *SamrCloseHandle) (
    __inout SAMPR_HANDLE * SamHandle
    );

// opnum 7
typedef NTSTATUS  (NTAPI *SamrOpenDomain) (
    __in SAMPR_HANDLE ServerHandle,
    __in DWORD   DesiredAccess,
    __in PSID DomainId,
    __out SAMPR_HANDLE * DomainHandle
    );


		// opnum 34
typedef NTSTATUS  (NTAPI *SamrOpenUser) (
    __in SAMPR_HANDLE DomainHandle,
    __in DWORD   DesiredAccess,
    __in DWORD   UserId,
    __out SAMPR_HANDLE  * UserHandle
    );

// opnum 36
typedef NTSTATUS  (NTAPI *SamrQueryInformationUser) (
    __in SAMPR_HANDLE UserHandle,
    __in USER_INFORMATION_CLASS  UserInformationClass,
	__out PSAMPR_USER_INFO_BUFFER * Buffer
    );

typedef NTSTATUS  (NTAPI *SamIFree_SAMPR_USER_INFO_BUFFER) (
	__in PSAMPR_USER_INFO_BUFFER Buffer, 
	__in USER_INFORMATION_CLASS UserInformationClass
	);

HMODULE samsrvDll = NULL;
SamrConnect MySamrConnect;
SamrCloseHandle MySamrCloseHandle;
SamrOpenDomain MySamrOpenDomain;
SamrOpenUser MySamrOpenUser;
SamrQueryInformationUser MySamrQueryInformationUser;
SamIFree_SAMPR_USER_INFO_BUFFER MySamIFree;


NTSTATUS LoadSamSrv()
{
	samsrvDll = LoadLibrary(TEXT("samsrv.dll"));
	if (!samsrvDll)
	{
		EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"LoadSam failed %d",GetLastError());
		return STATUS_FAIL_CHECK;
	}
	MySamrConnect = (SamrConnect) GetProcAddress(samsrvDll,"SamIConnect");
	MySamrCloseHandle = (SamrCloseHandle) GetProcAddress(samsrvDll,"SamrCloseHandle");
	MySamrOpenDomain = (SamrOpenDomain) GetProcAddress(samsrvDll,"SamrOpenDomain");
	MySamrOpenUser = (SamrOpenUser) GetProcAddress(samsrvDll,"SamrOpenUser");
	MySamrQueryInformationUser = (SamrQueryInformationUser) GetProcAddress(samsrvDll,"SamrQueryInformationUser");
	MySamIFree = (SamIFree_SAMPR_USER_INFO_BUFFER) GetProcAddress(samsrvDll,"SamIFree_SAMPR_USER_INFO_BUFFER");
	if (!MySamrConnect || !MySamrCloseHandle || !MySamrOpenDomain || !MySamrOpenUser
		|| !MySamrQueryInformationUser || !MySamIFree)
	{
		EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Null pointer function");
		FreeLibrary(samsrvDll);
		return STATUS_FAIL_CHECK;
	}
	return STATUS_SUCCESS;
}

NTSTATUS GetPasswordFromSam( __in PSID UserSid, __out unsigned char * Password)
{
	NTSTATUS Status = STATUS_SUCCESS;
	LSA_OBJECT_ATTRIBUTES connectionAttrib;
    LSA_HANDLE handlePolicy = NULL;
    PPOLICY_ACCOUNT_DOMAIN_INFO structInfoPolicy = NULL;// -> http://msdn2.microsoft.com/en-us/library/ms721895(VS.85).aspx.
	samsrvDll = NULL;
	SAMPR_HANDLE hSam = NULL, hDomain = NULL, hUser = NULL;
	PSAMPR_USER_INTERNAL1_INFORMATION UserInfo = NULL;
	EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Enter");
	__try
	{
		if (!IsValidSid(UserSid))
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"UserSid invalid");
			__leave;
		}
		Status = LoadSamSrv();
		if (Status!= STATUS_SUCCESS)
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"LoadSamSrv failed %d",Status);
			__leave;
		}

        memset(&connectionAttrib,0,sizeof(LSA_OBJECT_ATTRIBUTES));
        connectionAttrib.Length = sizeof(LSA_OBJECT_ATTRIBUTES);

		Status = LsaOpenPolicy(NULL,&connectionAttrib,POLICY_ALL_ACCESS,&handlePolicy);
		if (Status!= STATUS_SUCCESS)
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"LsaOpenPolicy failed %d",Status);
			__leave;
		}
		Status = LsaQueryInformationPolicy(handlePolicy , PolicyAccountDomainInformation , (PVOID*)&structInfoPolicy);
		if (Status!= STATUS_SUCCESS)
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"LsaQueryInformationPolicy failed %d",Status);
			__leave;
		}
		Status = MySamrConnect(NULL , &hSam , MAXIMUM_ALLOWED, 1);
		if (Status!= STATUS_SUCCESS)	
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"MySamrConnect failed %d",Status);
			__leave;
		}
		Status = MySamrOpenDomain(hSam , 0xf07ff , structInfoPolicy->DomainSid , &hDomain);
		if (Status!= STATUS_SUCCESS)	
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"MySamrOpenDomain failed %d",Status);
			__leave;
		}
		DWORD dwRid = *GetSidSubAuthority(UserSid,*GetSidSubAuthorityCount(UserSid) -1);
		Status = MySamrOpenUser(hDomain , MAXIMUM_ALLOWED , dwRid , &hUser);
		if (Status!= STATUS_SUCCESS)	
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"MySamrOpenUser failed %d rid = %d",Status,dwRid);
			__leave;
		}
		Status = MySamrQueryInformationUser(hUser , UserInternal1Information , &UserInfo);
		if (Status!= STATUS_SUCCESS)	
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"MySamrQueryInformationUser failed %d",Status);
			__leave;
		}
		DWORD i;
		for (i = 0; i<16; i++)
		{
			//wsprintf(Password + i*2 , L"%02X",UserInfo->EncryptedNtOwfPassword.data[i]);
			
			Password[i] =  UserInfo->EncryptedNtOwfPassword.data[i];
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Password %02X",Password[i]);
		}
		//EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Password %s",Password);
/*		WCHAR out[256]= L"";
		DWORD dwLen = 256;
		CRED_PROTECTION_TYPE type = CredTrustedProtection ;
		Status = CredProtect(FALSE, Password, 33, out, &dwLen, &type);
		EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Satus = %d out = %d out = %s",Status,dwLen,out);*/

	}
	__finally
	{
		if (UserInfo)
			MySamIFree(UserInfo, UserInternal1Information);
		EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"1");
		if (hUser)
			MySamrCloseHandle(&hUser);
		EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"2");
		if (hDomain)
			MySamrCloseHandle(&hDomain);
		EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"3");
		if (hSam)
			MySamrCloseHandle(&hSam);
		EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"4");
		if (structInfoPolicy)
			LsaFreeMemory(structInfoPolicy);
		EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"5");
		if (handlePolicy)
			LsaClose(handlePolicy);
		EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"6");
		if (samsrvDll) 
			FreeLibrary(samsrvDll);
		EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"7");
	}
	EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Leave with status = %d",Status);
	return Status;
}