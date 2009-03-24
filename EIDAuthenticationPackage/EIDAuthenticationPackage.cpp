
//#include <stdio.h>
//#include <winnt.h>
#include <ntstatus.h>
#define WIN32_NO_STATUS 1

#include <windows.h>

#include <winscard.h>
#include <Ntsecapi.h>
#include <credentialprovider.h>
#include <wincred.h>

#define SECURITY_WIN32
#include <sspi.h>

#include <ntsecpkg.h>
#include <subauth.h>

#include <iphlpapi.h>
#include <tchar.h>

#include "../EIDCardLibrary/EIDCardLibrary.h"
#include "../EIDCardLibrary/Tracing.h"
#include "../EIDCardLibrary/CompleteToken.h"
#include "../EIDCardLibrary/CompleteProfile.h"
#include "../EIDCardLibrary/Package.h"
#include "../EIDCardLibrary/CertificateValidation.h"
#include "../EIDCardLibrary/CompletePrimaryCredential.h"
#include "../EIDCardLibrary/StoredCredentialManagement.h"
#include "../EIDCardLibrary/Registration.h"

	
extern "C"
{
	// Save LsaDispatchTable
	PLSA_SECPKG_FUNCTION_TABLE MyLsaDispatchTable;

	// allocate an LSA_STRING from a char*
	PLSA_STRING LsaInitializeString(PCHAR Source)
	{
		size_t Size = strlen(Source);
		PCHAR Buffer = (PCHAR)MyLsaDispatchTable->AllocateLsaHeap(sizeof(CHAR)*(Size+1));
		if (Buffer == NULL) {
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"No Memory Buffer");
			return NULL;
		}

		PLSA_STRING Destination = (PLSA_STRING)MyLsaDispatchTable->AllocateLsaHeap(sizeof(LSA_STRING));

		if (Destination == NULL) {
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"No Memory Destination");
			MyLsaDispatchTable->FreeLsaHeap(Buffer);
			return NULL;
		}

		strncpy_s(Buffer,sizeof(CHAR)*(Size+1),
			Source,sizeof(CHAR)*(Size+1));
		Destination->Length = (USHORT) ( sizeof(CHAR)*Size);
		Destination->MaximumLength = (USHORT) (sizeof(CHAR)*(Size+1));
		Destination->Buffer = Buffer;
		return Destination;
	}

	PLSA_UNICODE_STRING LsaInitializeUnicodeStringFromWideString(PWSTR Source)
	{
		DWORD Size = sizeof(WCHAR)*wcslen(Source);
		PWSTR Buffer = (PWSTR)MyLsaDispatchTable->AllocateLsaHeap(Size+sizeof(WCHAR));
		if (Buffer == NULL) {
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"No Memory Buffer");
			return NULL;
		}

		PLSA_UNICODE_STRING Destination = (PLSA_UNICODE_STRING)MyLsaDispatchTable->AllocateLsaHeap(sizeof(LSA_UNICODE_STRING));

		if (Destination == NULL) {
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"No Memory Destination");
			MyLsaDispatchTable->FreeLsaHeap(Buffer);
			return NULL;
		}

		wcsncpy_s(Buffer,Size+sizeof(WCHAR),
			Source,Size+sizeof(WCHAR));
		Destination->Length = (USHORT) (Size);
		Destination->MaximumLength = (USHORT) (Size+sizeof(WCHAR));
		Destination->Buffer = Buffer;
		return Destination;
	}

	PLSA_UNICODE_STRING LsaInitializeUnicodeStringFromUnicodeString(UNICODE_STRING Source)
	{
		PLSA_UNICODE_STRING Destination;
		Destination = (PLSA_UNICODE_STRING)MyLsaDispatchTable->AllocateLsaHeap(sizeof(LSA_UNICODE_STRING));
		if (Destination == NULL) {
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"No Memory Destination");
			return NULL;
		}
		Destination->Buffer = (WCHAR*)MyLsaDispatchTable->AllocateLsaHeap(Source.Length+sizeof(WCHAR));
		if (Destination->Buffer == NULL) {
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"No Memory Destination->Buffer");
			MyLsaDispatchTable->FreeLsaHeap(Destination);
			return NULL;
		}
		Destination->Length = Source.Length;
		Destination->MaximumLength = Source.Length + sizeof(WCHAR);
		memcpy_s(Destination->Buffer,Destination->Length,Source.Buffer,Source.Length);
		Destination->Buffer[Destination->Length/2] = 0;
		EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Destination OK '%wZ'",Destination);
		return Destination;
	}

	void NTAPI DllRegister()
	{
		EIDAuthenticationPackageDllRegister();
		EIDCredentialProviderDllRegister();
		EIDPasswordChangeNotificationDllRegister();
		EIDConfigurationWizardDllRegister();
	}

	void NTAPI DllUnRegister()
	{
		EIDAuthenticationPackageDllUnRegister();
		EIDCredentialProviderDllUnRegister();
		EIDPasswordChangeNotificationDllUnRegister();
		EIDConfigurationWizardDllUnRegister();
	}

	void NTAPI DllEnableLogging()
	{
		EnableLogging();
	}

	void NTAPI DllDisableLogging()
	{
		DisableLogging();
	}

	/** Called when the authentication package's identifier has been specified in a call
	to LsaCallAuthenticationPackage by an application using an untrusted connection. 
	This function is used for communicating with processes that do not have the SeTcbPrivilege privilege.*/

	NTSTATUS NTAPI LsaApCallPackageUntrusted(
	  __in   PLSA_CLIENT_REQUEST ClientRequest,
	  __in   PVOID ProtocolSubmitBuffer,
	  __in   PVOID ClientBufferBase,
	  __in   ULONG SubmitBufferLength,
	  __out  PVOID *ProtocolReturnBuffer,
	  __out  PULONG ReturnBufferLength,
	  __out  PNTSTATUS ProtocolStatus
	) 
	{
		PBYTE pPointer;
		BOOL fStatus;
		SECPKG_CLIENT_INFO ClientInfo;
		NTSTATUS status = STATUS_INVALID_MESSAGE;
		UNREFERENCED_PARAMETER(ClientRequest);
		UNREFERENCED_PARAMETER(ReturnBufferLength);
		UNREFERENCED_PARAMETER(ProtocolReturnBuffer);
		UNREFERENCED_PARAMETER(ProtocolStatus);
		UNREFERENCED_PARAMETER(SubmitBufferLength);
		__try
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Enter");
			PEID_CALLPACKAGE_BUFFER pBuffer = (PEID_CALLPACKAGE_BUFFER) ProtocolSubmitBuffer;
			pBuffer->dwError = 0;
			switch (pBuffer->MessageType)
			{
			case EIDCMCreateStoredCredential:
				EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"EIDCMCreateStoredCredential");
				if (STATUS_SUCCESS != MyLsaDispatchTable->GetClientInfo(&ClientInfo))
				{
					EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"GetClientInfo");
					break;
				}
				if (!MatchUserOrIsAdmin(pBuffer->dwRid, &(ClientInfo)))
				{
					EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Not autorized");
					break;
				}
				pPointer = (PBYTE) pBuffer->szPassword - (ULONG) ClientBufferBase + (ULONG) pBuffer;
				pBuffer->szPassword = (PWSTR) pPointer;
				//pPointer = (PBYTE) pBuffer->szProvider - (ULONG) ClientBufferBase + (ULONG) pBuffer;
				//pBuffer->szProvider = (PWSTR) pPointer;
				//pPointer = (PBYTE) pBuffer->szContainer - (ULONG) ClientBufferBase + (ULONG) pBuffer;
				//pBuffer->szContainer = (PWSTR) pPointer;
				pPointer = (PBYTE) pBuffer->pbPublicKey - (ULONG) ClientBufferBase + (ULONG) pBuffer;
				pBuffer->pbPublicKey = (PBYTE) pPointer;
				//fStatus = CreateStoredCredential(pBuffer->dwRid, pBuffer->szPassword, 0, pBuffer->szProvider,
				//		pBuffer->szContainer, pBuffer->dwKeySpec);
				fStatus = UpdateStoredCredentialEx(pBuffer->dwRid, pBuffer->szPassword, 0, pBuffer->pbPublicKey, 
					pBuffer->dwPublicKeySize, pBuffer->fEncryptPassword);
				if (!fStatus)
				{
					pBuffer->dwError = GetLastError();
				}
				else
				{
					status = STATUS_SUCCESS;
				}
				break;
			case EIDCMRemoveStoredCredential:
				EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"EIDCMRemoveStoredCredential");
				if (STATUS_SUCCESS != MyLsaDispatchTable->GetClientInfo(&ClientInfo))
				{
					EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"GetClientInfo");
					break;
				}
				if (!MatchUserOrIsAdmin(pBuffer->dwRid, &(ClientInfo)))
				{
					EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Not autorized");
					break;
				}
				fStatus = RemoveStoredCredential(pBuffer->dwRid);
				if (!fStatus)
				{
					pBuffer->dwError = GetLastError();
				}
				else
				{
					status = STATUS_SUCCESS;
				}
				break;
			case EIDCMHasStoredCredential:
				EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"EIDCMHasStoredCredential");
				if (STATUS_SUCCESS != MyLsaDispatchTable->GetClientInfo(&ClientInfo))
				{
					EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"GetClientInfo");
					break;
				}
				if (!MatchUserOrIsAdmin(pBuffer->dwRid, &(ClientInfo)))
				{
					EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Not autorized");
					break;
				}
				fStatus = HasStoredCredential(pBuffer->dwRid);
				if (!fStatus)
				{
					pBuffer->dwError = GetLastError();
				}
				else
				{
					status = STATUS_SUCCESS;
				}
				break;
			case EIDCMTest:
				HANDLE hLsa;
				if (LsaConnectUntrusted(&hLsa) == STATUS_SUCCESS)
				{

					ULONG ulAuthPackage;
					LSA_STRING lsaszPackageName;
					LsaInitString(&lsaszPackageName, "Negotiate");

					status = LsaLookupAuthenticationPackage(hLsa, &lsaszPackageName, &ulAuthPackage);
					if (STATUS_SUCCESS != status)
					{
						EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"LsaLookupAuthenticationPackage 0x%08X",status);
						break;
					}
					CHAR PrimaryKeyBuffer[1000];
					LSA_STRING PrimaryKey = {ARRAYSIZE(PrimaryKeyBuffer),ARRAYSIZE(PrimaryKeyBuffer),PrimaryKeyBuffer};
					ULONG QueryContext = 0;
					LSA_STRING Credentials;
					EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"EIDCMTest");
					status = MyLsaDispatchTable->GetClientInfo(&ClientInfo);
					if (STATUS_SUCCESS != status)
					{
						EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"GetClientInfo 0x%08X",status);
						break;
					}
					status = STATUS_SUCCESS;
					while(status == STATUS_SUCCESS)
					{
						ULONG PrimaryKeyLength = PrimaryKey.MaximumLength;
						Credentials.Buffer = NULL;
						Credentials.Length = 0;
						Credentials.MaximumLength = 0;
						status = MyLsaDispatchTable->GetCredentials(&(ClientInfo.LogonId), ulAuthPackage, &QueryContext, TRUE, &PrimaryKey, &PrimaryKeyLength, &Credentials);
						if (status == STATUS_SUCCESS)
						{
							EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Key = %Z",PrimaryKey);	
							EIDCardLibraryDumpMemory((PUCHAR) Credentials.Buffer,Credentials.Length);
							MyLsaDispatchTable->FreeLsaHeap(Credentials.Buffer);
						}
						else
						{
							EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"GetCredentials 0x%08X",status);
						}
					}
					LsaClose(hLsa);
				}
				else
				{
					EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"LsaConnectUntrusted 0x%08X",status);
					break;
				}
				break;
			default:
				EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Invalid message %d",pBuffer->MessageType);
			}
			// copy error back to original buffer
			if ( STATUS_SUCCESS != MyLsaDispatchTable->CopyToClientBuffer(ClientRequest, sizeof(DWORD), &(pBuffer->dwError)  + (ULONG) ClientBufferBase - (ULONG) pBuffer, &(pBuffer->dwError)))
			{
				EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"CopyToClientBuffer failed");
			}
			return status;
		}
			// disable warning because we want to trap ALL exception
#pragma warning(push)
#pragma warning(disable : 6320)
	__except(EXCEPTION_EXECUTE_HANDLER)
#pragma warning(pop)
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"NT exception 0x%08x",GetExceptionCode());
			return GetExceptionCode();
		}
	}


		/** Called when the authentication package's identifier has been specified in a call to 
	LsaCallAuthenticationPackage by an application that is using a trusted connection.

	This function provides a way for logon applications to communicate directly with authentication packages.*/

	NTSTATUS NTAPI LsaApCallPackage(
	  __in   PLSA_CLIENT_REQUEST ClientRequest,
	  __in   PVOID ProtocolSubmitBuffer,
	  __in   PVOID ClientBufferBase,
	  __in   ULONG SubmitBufferLength,
	  __out  PVOID *ProtocolReturnBuffer,
	  __out  PULONG ReturnBufferLength,
	  __out  PNTSTATUS ProtocolStatus
	) {
		EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"");
		return LsaApCallPackageUntrusted(ClientRequest,ProtocolSubmitBuffer,ClientBufferBase,
			SubmitBufferLength,ProtocolReturnBuffer,ReturnBufferLength,ProtocolStatus);
	}  

	/**
	Called when the authentication package's identifier has been specified in
	a call to LsaCallAuthenticationPackage for a pass-through logon request.*/

	NTSTATUS NTAPI LsaApCallPackagePassthrough(
	  __in   PLSA_CLIENT_REQUEST ClientRequest,
	  __in   PVOID ProtocolSubmitBuffer,
	  __in   PVOID ClientBufferBase,
	  __in   ULONG SubmitBufferLength,
	  __out  PVOID *ProtocolReturnBuffer,
	  __out  PULONG ReturnBufferLength,
	  __out  PNTSTATUS ProtocolStatus
	) {
		EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"");
		return LsaApCallPackageUntrusted(ClientRequest,ProtocolSubmitBuffer,ClientBufferBase,
			SubmitBufferLength,ProtocolReturnBuffer,ReturnBufferLength,ProtocolStatus);
	}

	/** Called during system initialization to permit the authentication package to perform
	initialization tasks.*/

	NTSTATUS NTAPI LsaApInitializePackage(
	  __in      ULONG AuthenticationPackageId,
	  __in      PLSA_DISPATCH_TABLE LsaDispatchTable,
	  __in_opt  PLSA_STRING Database,
	  __in_opt  PLSA_STRING Confidentiality,
	  __out     PLSA_STRING *AuthenticationPackageName
	) {
		UNREFERENCED_PARAMETER(AuthenticationPackageId);
		UNREFERENCED_PARAMETER(Database);
		UNREFERENCED_PARAMETER(Confidentiality);

		EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"AuthenticationPackageName = %S",AUTHENTICATIONPACKAGENAME);
		NTSTATUS Status = STATUS_SUCCESS;

		MyLsaDispatchTable = (PLSA_SECPKG_FUNCTION_TABLE)LsaDispatchTable;

		*AuthenticationPackageName = LsaInitializeString(AUTHENTICATIONPACKAGENAME);
		EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Leave");
		return Status;
	}

	/** Called when a logon session ends to permit the authentication package 
	to free any resources allocated for the logon session.*/

	VOID NTAPI LsaApLogonTerminated(
	  __in  PLUID LogonId
	) {
		UNREFERENCED_PARAMETER(LogonId);
		return;
	}

	/** Called when the authentication package has been specified in a call to LsaLogonUser.
	This function authenticates a security principal's logon data.*/

	NTSTATUS NTAPI LsaApLogonUserEx2(
	  __in   PLSA_CLIENT_REQUEST ClientRequest,
	  __in   SECURITY_LOGON_TYPE LogonType,
	  __in   PVOID AuthenticationInformation,
	  __in   PVOID ClientAuthenticationBase,
	  __in   ULONG AuthenticationInformationLength,
	  __out  PVOID *ProfileBuffer,
	  __out  PULONG ProfileBufferLength,
	  __out  PLUID LogonId,
	  __out  PNTSTATUS SubStatus,
	  __out  PLSA_TOKEN_INFORMATION_TYPE TokenInformationType,
	  __out  PVOID *TokenInformation,
	  __out  PLSA_UNICODE_STRING *AccountName,
	  __out  PLSA_UNICODE_STRING *AuthenticatingAuthority,
	  __out  PUNICODE_STRING *MachineName,
 	  __out  PSECPKG_PRIMARY_CRED PrimaryCredentials,
	  __out  PSECPKG_SUPPLEMENTAL_CRED_ARRAY *SupplementalCredentials
	) 
	{
		UNREFERENCED_PARAMETER(AuthenticationInformationLength);
		
		NTSTATUS Status;
		DWORD dwLen = MAX_COMPUTERNAME_LENGTH;
		WCHAR ComputerName[MAX_COMPUTERNAME_LENGTH + 1];
		DWORD TokenLength;
		CRED_PROTECTION_TYPE protectionType;
		WCHAR pwzPin[UNLEN];
		WCHAR pwzPinUncrypted[UNLEN];
		DWORD dPinUncrypted = UNLEN;
		LPWSTR pPin = pwzPin;
		PCCERT_CONTEXT pCertContext = NULL;
		LPTSTR szUserName = NULL;
		DWORD dwError;
		PLSA_TOKEN_INFORMATION_V2 MyTokenInformation = NULL;
		__try
		{
			if (SubStatus) *SubStatus = STATUS_SUCCESS;

			EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Enter");
			EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"LogonType = %d",LogonType);
			

			PEID_INTERACTIVE_UNLOCK_LOGON pUnlockLogon = (PEID_INTERACTIVE_UNLOCK_LOGON) AuthenticationInformation;
			RemapPointer(pUnlockLogon,ClientAuthenticationBase);
			PEID_SMARTCARD_CSP_INFO pSmartCardCspInfo = (PEID_SMARTCARD_CSP_INFO) pUnlockLogon->Logon.CspData;
			EIDDebugPrintEIDUnlockLogonStruct(WINEVENT_LEVEL_VERBOSE, pUnlockLogon);
			

			// set AccountName which is mandatory
			EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"AccountName");
			*AccountName = LsaInitializeUnicodeStringFromUnicodeString(pUnlockLogon->Logon.UserName);

			// set AuthenticatingAuthority / optional
			if (pUnlockLogon->Logon.LogonDomainName.Length == 0)
			{
				*AuthenticatingAuthority = NULL;
				EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"LogonDomainName NULL");
				return STATUS_BAD_VALIDATION_CLASS;
			}

			*AuthenticatingAuthority = LsaInitializeUnicodeStringFromUnicodeString(pUnlockLogon->Logon.LogonDomainName);
			EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"AuthenticatingAuthority OK");
			
			if (GetComputerName(ComputerName, &dwLen))
			{
				*MachineName = LsaInitializeUnicodeStringFromWideString(ComputerName);
			}
			else
			{
				*MachineName = NULL;
			}
			EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"MachineName OK");

			// get / decrypt PIN

			memcpy_s(pwzPin,UNLEN*sizeof(WCHAR),pUnlockLogon->Logon.Pin.Buffer,pUnlockLogon->Logon.Pin.Length);
			pwzPin[pUnlockLogon->Logon.Pin.Length/sizeof(WCHAR)] = 0;
			if(CredIsProtectedW(pwzPin, &protectionType))
			{
				if(CredUnprotected != protectionType)
				{
					if (!CredUnprotectW(FALSE,pwzPin,UNLEN,pwzPinUncrypted,&dPinUncrypted))
					{
						EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"CredUnprotectW %d",GetLastError());
						return STATUS_BAD_VALIDATION_CLASS;
					}
					pPin = pwzPinUncrypted;
					//EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"PIN = %s",pwzPinUncrypted);
				}
			}
			
			// do security check
			pCertContext = GetCertificateFromCspInfo(pSmartCardCspInfo);
			if (!pCertContext) {
				EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Unable to create certificate from logon info");
				return STATUS_LOGON_FAILURE;
			}

			// username = username on certificate
			szUserName = GetUserNameFromCertificate(pCertContext);
			if (!szUserName) {
				EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Username from cert null");
				return STATUS_LOGON_FAILURE;
			}
			if ((wcslen(szUserName) != (size_t) (pUnlockLogon->Logon.UserName.Length/2))
				|| (wcsncmp(szUserName,pUnlockLogon->Logon.UserName.Buffer,pUnlockLogon->Logon.UserName.Length/2) != 0))
			{
				EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Username <>");
				return STATUS_LOGON_FAILURE;
			}
			delete[] szUserName;
			if (!IsTrustedCertificate(pCertContext,&dwError))
			{
				EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Untrusted certificate 0x%x",dwError);
				return STATUS_LOGON_FAILURE;
			}


			// create token
			EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"TokenInformation ?");
			Status = UserNameToToken(*AuthenticatingAuthority,*AccountName,(PLSA_DISPATCH_TABLE)MyLsaDispatchTable,
						&MyTokenInformation,&TokenLength, SubStatus);
			if (Status != STATUS_SUCCESS) 
			{
				EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"UserNameToToken failed %d",Status);
				return Status;
			}
			EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"TokenInformation OK");
			PSID pSid = MyTokenInformation->User.User.Sid;
			DWORD dwRid = *GetSidSubAuthority(pSid,*GetSidSubAuthorityCount(pSid) -1);
			EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"RID = %d", dwRid);
			PWSTR szPassword = NULL;
			if (!RetrieveStoredCredential(dwRid,pCertContext, pPin, &szPassword))
			{
				EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"RetrieveStoredCredential failed");
				MyLsaDispatchTable->FreeLsaHeap(MyTokenInformation);
				return STATUS_SMARTCARD_WRONG_PIN;
			}
			EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"RetrieveStoredCredential OK");
EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Password = %s",szPassword);

			CertFreeCertificateContext(pCertContext);

			*TokenInformation = MyTokenInformation;
			*TokenInformationType = LsaTokenInformationV2;
			

			// create session
			if (!AllocateLocallyUniqueId (LogonId))
			{
				MyLsaDispatchTable->FreeLsaHeap (*TokenInformation);
				*TokenInformation = NULL;
				EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"No Memory logon_id");
				return STATUS_INSUFFICIENT_RESOURCES;
			}
			EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"AllocateLocallyUniqueId OK");
			Status = MyLsaDispatchTable->CreateLogonSession (LogonId);
			if (Status != STATUS_SUCCESS)
			{
				MyLsaDispatchTable->FreeLsaHeap (*TokenInformation);
				*TokenInformation = NULL;
				EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"CreateLogonSession %d",Status);
				return Status;
			}
			EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"CreateLogonSession OK");

			// create profile

			// undocumented feature : if this buffer (which is not mandatory) is not filled
			// vista login WILL crash
			Status = UserNameToProfile(*AuthenticatingAuthority,*AccountName,(PLSA_DISPATCH_TABLE)MyLsaDispatchTable,
						ClientRequest,(PEID_INTERACTIVE_PROFILE*)ProfileBuffer,ProfileBufferLength);
			EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"ProfileBuffer OK Status = %d",Status);

			// create primary credentials

			Status = CompletePrimaryCredential(*AuthenticatingAuthority,*AccountName,pSid,LogonId,szPassword,(PLSA_DISPATCH_TABLE)MyLsaDispatchTable,PrimaryCredentials);
			EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"CompletePrimaryCredential OK Status = %d",Status);
			*SupplementalCredentials = (PSECPKG_SUPPLEMENTAL_CRED_ARRAY) MyLsaDispatchTable->AllocateLsaHeap(sizeof(SECPKG_SUPPLEMENTAL_CRED_ARRAY));
			if (*SupplementalCredentials)
			{
				(*SupplementalCredentials)->CredentialCount = 0;
			}
			if (szPassword)
			{
				SecureZeroMemory(szPassword, wcslen(szPassword) * sizeof(WCHAR));
				free(szPassword);
			}
			Status = STATUS_SUCCESS;
			*SubStatus = STATUS_SUCCESS;

			EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Success !!");
			return Status;
		}
// disable warning because we want to trap ALL exception
#pragma warning(push)
#pragma warning(disable : 6320)
	__except(EXCEPTION_EXECUTE_HANDLER)
#pragma warning(pop)
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"NT exception 0x%08x",GetExceptionCode());
			return GetExceptionCode();
		}

	}

}