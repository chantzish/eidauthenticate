/*	EID Authentication
    Copyright (C) 2009 Vincent Le Toux

    This library is free software; you can redistribute it and/or
    modify it under the terms of the GNU Lesser General Public
    License version 2.1 as published by the Free Software Foundation.

    This library is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
    Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public
    License along with this library; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/

//#include <stdio.h>
//#include <winnt.h>
#include <ntstatus.h>
#define WIN32_NO_STATUS 1

#include <windows.h>

#include <winscard.h>
#include <Ntsecapi.h>


#define SECURITY_WIN32
#include <sspi.h>

#include <ntsecpkg.h>
#include <subauth.h>
#include <credentialprovider.h>
#include <wincred.h>

#include <iphlpapi.h>
#include <tchar.h>

#include "../EIDCardLibrary/EIDCardLibrary.h"
#include "../EIDCardLibrary/Tracing.h"
#include "../EIDCardLibrary/CompleteToken.h"
#include "../EIDCardLibrary/CompleteProfile.h"
#include "../EIDCardLibrary/Package.h"
#include "../EIDCardLibrary/CertificateValidation.h"
#include "../EIDCardLibrary/StoredCredentialManagement.h"
#include "../EIDCardLibrary/SmartCardModule.h"

	
extern "C"
{
	// Save LsaDispatchTable
	extern PLSA_SECPKG_FUNCTION_TABLE MyLsaDispatchTable;
	// ref to function

	

	void initializeExportedFunctionsTable();

	// allocate an LSA_STRING from a char*
	PLSA_STRING LsaInitializeString(PCHAR Source)
	{
		size_t Size = strlen(Source);
		PCHAR Buffer = (PCHAR)EIDAlloc((DWORD) (sizeof(CHAR)*(Size+1)));
		if (Buffer == NULL) {
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"No Memory Buffer");
			return NULL;
		}

		PLSA_STRING Destination = (PLSA_STRING)EIDAlloc(sizeof(LSA_STRING));

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
		DWORD Size = (DWORD) (wcslen(Source));
		PWSTR Buffer = (PWSTR)EIDAlloc((DWORD) (Size+1) * sizeof(WCHAR));
		if (Buffer == NULL) {
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"No Memory Buffer");
			return NULL;
		}

		PLSA_UNICODE_STRING Destination = (PLSA_UNICODE_STRING)EIDAlloc(sizeof(LSA_UNICODE_STRING));

		if (Destination == NULL) {
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"No Memory Destination");
			MyLsaDispatchTable->FreeLsaHeap(Buffer);
			return NULL;
		}

		wcscpy_s(Buffer,Size+1,
			Source);
		Destination->Length = (USHORT) (Size * sizeof(WCHAR));
		Destination->MaximumLength = (USHORT) ((Size+1) * sizeof(WCHAR));
		Destination->Buffer = Buffer;
		return Destination;
	}

	PLSA_UNICODE_STRING LsaInitializeUnicodeStringFromUnicodeString(UNICODE_STRING Source)
	{
		PLSA_UNICODE_STRING Destination;
		Destination = (PLSA_UNICODE_STRING)EIDAlloc(sizeof(LSA_UNICODE_STRING));
		if (Destination == NULL) {
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"No Memory Destination");
			return NULL;
		}
		Destination->Buffer = (WCHAR*)EIDAlloc(Source.Length+sizeof(WCHAR));
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
		// don't fail
		Status = STATUS_SUCCESS;
		return Status;
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
		NTSTATUS statusError;
		PCCERT_CONTEXT pCertContext = NULL;
		PWSTR szUsername = NULL;
		UNREFERENCED_PARAMETER(ClientRequest);
		UNREFERENCED_PARAMETER(ReturnBufferLength);
		UNREFERENCED_PARAMETER(ProtocolReturnBuffer);
		UNREFERENCED_PARAMETER(SubmitBufferLength);
		__try
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Enter");
			*ProtocolStatus = STATUS_SUCCESS;
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
				EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Has Autorization for rid = 0x%x", pBuffer->dwRid);
				pPointer = (PBYTE) pBuffer->szPassword - (ULONG) ClientBufferBase + (ULONG) pBuffer;
				pBuffer->szPassword = (PWSTR) pPointer;
				pPointer = (PBYTE) pBuffer->pbCertificate - (ULONG) ClientBufferBase + (ULONG) pBuffer;
				pBuffer->pbCertificate = (PBYTE) pPointer;
				pCertContext = CertCreateCertificateContext(X509_ASN_ENCODING, pBuffer->pbCertificate, pBuffer->dwCertificateSize);
				if (!pCertContext)
				{
					pBuffer->dwError = GetLastError();
					EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"CertCreateCertificateContext 0x%08x", pBuffer->dwError);
					break;
				}
				EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Certificate created in memory");
				fStatus = CStoredCredentialManager::Instance()->CreateCredential(pBuffer->dwRid,pCertContext,pBuffer->szPassword, 0, pBuffer->fEncryptPassword);
				if (!fStatus)
				{
					pBuffer->dwError = GetLastError();
					EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Error 0x%08X",pBuffer->dwError);
				}
				status = STATUS_SUCCESS;
				CertFreeCertificateContext(pCertContext);
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
				EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Has Autorization for rid = 0x%x", pBuffer->dwRid);
				fStatus = CStoredCredentialManager::Instance()->RemoveStoredCredential(pBuffer->dwRid);
				if (!fStatus)
				{
					pBuffer->dwError = GetLastError();
					EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Error 0x%08X",pBuffer->dwError);
				}
				status = STATUS_SUCCESS;
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
				EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Has Autorization for rid = 0x%x", pBuffer->dwRid);
				fStatus = CStoredCredentialManager::Instance()->HasStoredCredential(pBuffer->dwRid);
				if (!fStatus)
				{
					pBuffer->dwError = GetLastError();
					if (pBuffer->dwError == 0)
					{
						pBuffer->dwError = ERROR_NOT_FOUND;
					}
					EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Error 0x%08X",pBuffer->dwError);
				}
				status = STATUS_SUCCESS;
				break;
			case EIDCMRemoveAllStoredCredential:
				EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"EIDCMRemoveAllStoredCredential");
				if (STATUS_SUCCESS != MyLsaDispatchTable->GetClientInfo(&ClientInfo))
				{
					EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"GetClientInfo");
					break;
				}
				if (!MatchUserOrIsAdmin(0, &(ClientInfo)))
				{
					EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Not autorized");
					break;
				}
				EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Has Autorization for rid = 0x%x", pBuffer->dwRid);
				fStatus = CStoredCredentialManager::Instance()->RemoveAllStoredCredential();
				if (!fStatus)
				{
					pBuffer->dwError = GetLastError();
					EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Error 0x%08X",pBuffer->dwError);
				}
				status = STATUS_SUCCESS;
				break;
			case EIDCMGetStoredCredentialRid:
				EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"EIDCMGetStoredCredentialRid");
				pPointer = (PBYTE) pBuffer->pbCertificate - (ULONG) ClientBufferBase + (ULONG) pBuffer;
				pBuffer->pbCertificate = (PBYTE) pPointer;
				pCertContext = CertCreateCertificateContext(X509_ASN_ENCODING, pBuffer->pbCertificate, pBuffer->dwCertificateSize);
				if (!pCertContext)
				{
					pBuffer->dwError = GetLastError();
					EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"CertCreateCertificateContext 0x%08x", pBuffer->dwError);
					break;
				}
				EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Certificate created in memory");
				fStatus = CStoredCredentialManager::Instance()->GetUsernameFromCertContext(pCertContext, &szUsername, &pBuffer->dwRid);
				if (!fStatus)
				{
					pBuffer->dwError = GetLastError();
					EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Error 0x%08X",pBuffer->dwError);
					status = STATUS_SUCCESS;
				}
				else
				{
					EIDFree(szUsername);
					status = STATUS_SUCCESS;
				}
				EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"copy back");
				// copy error back to original buffer
				MyLsaDispatchTable->CopyToClientBuffer(ClientRequest, sizeof(DWORD), ((PBYTE)&(pBuffer->dwRid))  + (ULONG) ClientBufferBase - (ULONG) pBuffer, &(pBuffer->dwRid));
				break;
			
			default:
				EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Invalid message %d",pBuffer->MessageType);
			}
			EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Done in LSA memory - preparing response");
			// copy error back to original buffer
			statusError= MyLsaDispatchTable->CopyToClientBuffer(ClientRequest, sizeof(DWORD), ((PBYTE)&(pBuffer->dwError))  + (ULONG) ClientBufferBase - (ULONG) pBuffer, &(pBuffer->dwError));
			if (STATUS_SUCCESS != statusError )
			{
				EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"CopyToClientBuffer failed");
			}
			
			EIDCardLibraryTrace(WINEVENT_LEVEL_INFO,L"return 0x%08X",status);
			return status;
		}
		__except(EIDExceptionHandler(GetExceptionInformation()))
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"NT exception 0x%08x",GetExceptionCode());
			return STATUS_LOGON_FAILURE;
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

	/** Called when a logon session ends to permit the authentication package 
	to free any resources allocated for the logon session.*/

	VOID NTAPI LsaApLogonTerminated(
	  __in  PLUID LogonId
	) {
		UNREFERENCED_PARAMETER(LogonId);
		return;
	}

	// these API aren't available in Windows XP
	// so we have to load them manually
	typedef BOOL (WINAPI *CredIsProtectedWFct)(
			__in LPWSTR                 pszProtectedCredentials,
			__out CRED_PROTECTION_TYPE* pProtectionType
			);
	typedef BOOL (WINAPI *CredUnprotectWFct) (
			__in BOOL                                   fAsSelf,
			__in_ecount(cchProtectedCredentials) LPWSTR pszProtectedCredentials,
			__in DWORD                                  cchProtectedCredentials,
			__out_ecount_opt(*pcchMaxChars) LPWSTR      pszCredentials,
			__inout DWORD*                              pcchMaxChars
			);
	NTSTATUS TryToUnprotecThePin(PWSTR pwzPin, PWSTR pwzPinUncrypted, DWORD dPinUncrypted, PWSTR *pResultingPin)
	{
		CRED_PROTECTION_TYPE protectionType;
		CredIsProtectedWFct CredIsProtectedW = NULL;
		CredUnprotectWFct CredUnprotectW = NULL;
		HMODULE hModule = NULL;
		NTSTATUS Status = STATUS_SUCCESS;
		__try
		{
			// default output : the PIN given to LSA (not crypted)
			*pResultingPin = pwzPin;
			// try to know if the PIN was crypted (Vista & later)
			hModule = LoadLibrary(TEXT("Advapi32.dll"));
			if (hModule == NULL)
			{
				__leave;
			}
			CredIsProtectedW = (CredIsProtectedWFct) GetProcAddress(hModule,"CredIsProtectedW");
			CredUnprotectW = (CredUnprotectWFct) GetProcAddress(hModule,"CredUnprotectW");
			if (CredIsProtectedW == NULL || CredUnprotectW == NULL)
			{
				// get here if on Windows XP
				__leave;
			}
			// here on Vista & later
			if(CredIsProtectedW(pwzPin, &protectionType))
			{
				if(CredUnprotected != protectionType)
				{
					if (!CredUnprotectW(FALSE,pwzPin,UNLEN,pwzPinUncrypted,&dPinUncrypted))
					{
						EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"CredUnprotectW 0x%08x",GetLastError());
						Status = STATUS_BAD_VALIDATION_CLASS;
						__leave;
					}
					//EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"PIN = %s",pwzPinUncrypted);
					// the PIN was crypted - use the uncrypted PIN
					*pResultingPin = pwzPinUncrypted;
				}
			}
		}
		__finally
		{
			if (hModule != NULL)
				FreeLibrary(hModule);
		}
		return Status;
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
	  __out  PUNICODE_STRING *AccountName,
	  __out  PUNICODE_STRING *AuthenticatingAuthority,
	  __out  PUNICODE_STRING *MachineName,
 	  __out  PSECPKG_PRIMARY_CRED PrimaryCredentials,
	  __out  PSECPKG_SUPPLEMENTAL_CRED_ARRAY *SupplementalCredentials
	) 
	{
		UNREFERENCED_PARAMETER(AuthenticationInformationLength);
		EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Enter");
		NTSTATUS Status;
		DWORD dwLen = MAX_COMPUTERNAME_LENGTH +1;
		WCHAR ComputerName[MAX_COMPUTERNAME_LENGTH + 1];
		DWORD TokenLength;
		WCHAR pwzPin[UNLEN] = L"";
		WCHAR pwzPinUncrypted[UNLEN] = L"";
		DWORD dPinUncrypted = UNLEN;
		LPWSTR pPin = pwzPin;
		PCCERT_CONTEXT pCertContext = NULL;
		LPTSTR szUserName = NULL;
		PLSA_TOKEN_INFORMATION_V2 MyTokenInformation = NULL;
		DWORD dwRid = 0;
		__try
		{
			*SubStatus = STATUS_SUCCESS;

			EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"LogonType = %d",LogonType);
			
			// the buffer come from another address space
			// so the pointers inside the buffer are invalid
			PEID_INTERACTIVE_UNLOCK_LOGON pUnlockLogon = (PEID_INTERACTIVE_UNLOCK_LOGON) AuthenticationInformation;
			RemapPointer(pUnlockLogon,ClientAuthenticationBase);
			PEID_SMARTCARD_CSP_INFO pSmartCardCspInfo = (PEID_SMARTCARD_CSP_INFO) pUnlockLogon->Logon.CspData;
			EIDDebugPrintEIDUnlockLogonStruct(WINEVENT_LEVEL_VERBOSE, pUnlockLogon);
			
			CStoredCredentialManager* manager = CStoredCredentialManager::Instance();
			if (!manager)
			{
				EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"manager NULL");
				return STATUS_BAD_VALIDATION_CLASS;
			}

			if (GetComputerName(ComputerName, &dwLen))
			{
				*MachineName = LsaInitializeUnicodeStringFromWideString(ComputerName);
				*AuthenticatingAuthority = LsaInitializeUnicodeStringFromWideString(ComputerName);
			}
			else
			{
				EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"GetComputerName NULL 0x%08x",GetLastError());
				return STATUS_BAD_VALIDATION_CLASS;
			}
			EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"MachineName OK");

			// get / decrypt PIN

			memcpy_s(pwzPin,UNLEN*sizeof(WCHAR),pUnlockLogon->Logon.Pin.Buffer,pUnlockLogon->Logon.Pin.Length);
			pwzPin[pUnlockLogon->Logon.Pin.Length/sizeof(WCHAR)] = 0;
			Status = TryToUnprotecThePin(pwzPin,pwzPinUncrypted, dPinUncrypted, &pPin);
			if (Status != STATUS_SUCCESS)
			{
				EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"TryToUnprotecThePin 0x%08X", Status);
				return Status;
			}
			// impersonate the client to beneficiate from the smart card redirection
			// if enabled on terminal session
			
			// check the PIN if using the base smart card provider to get the remaining pin attempts
			// put the result in SubStatus
			Status = CheckPINandGetRemainingAttemptsIfPossible(pSmartCardCspInfo, pPin, SubStatus);
			if (Status != STATUS_SUCCESS)
			{
				EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"CheckPINandGetRemainingAttemptsIfPossible 0x%08X", Status);
				return Status;
			}

			pCertContext = GetCertificateFromCspInfo(pSmartCardCspInfo);
			if (!pCertContext) {
				EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Unable to create certificate from logon info");
				return STATUS_LOGON_FAILURE;
			}
			
			// username = username on certificate
			if (!manager->GetUsernameFromCertContext(pCertContext, &szUserName, &dwRid))
			{
				EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"GetUsernameFromCertContext 0x%08x",GetLastError());
				return STATUS_LOGON_FAILURE;
			}
			if (!szUserName) {
				EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Username from cert null");
				return STATUS_LOGON_FAILURE;
			}
			*AccountName = LsaInitializeUnicodeStringFromWideString(szUserName);
			// trusted ?
			// check done after username to do accounting in case of failure
			// AccountName is known !
			if (!IsTrustedCertificate(pCertContext))
			{
				EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Untrusted certificate 0x%08x",GetLastError());
				return STATUS_LOGON_FAILURE;
			}
			
			EIDFree(szUserName);


			// create token
			EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"TokenInformation ?");
			Status = UserNameToToken(*AccountName,&MyTokenInformation,&TokenLength, SubStatus);
			if (Status != STATUS_SUCCESS) 
			{
				EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"UserNameToToken failed %d",Status);
				return STATUS_LOGON_FAILURE;
			}
			
			EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"TokenInformation OK substatus = 0x%08X",*SubStatus);
			*SubStatus = STATUS_SUCCESS;


			EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"RID = 0x%x", dwRid);
			PWSTR szPassword = NULL;
			
			if (!manager->GetPassword(dwRid,pCertContext, pPin, &szPassword))
			{
				DWORD dwError = GetLastError();
				EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"RetrieveStoredCredential failed %d", dwError);
				MyLsaDispatchTable->FreeLsaHeap(MyTokenInformation);
				switch(dwError)
				{
					case 0x80090015:
						return STATUS_SMARTCARD_NO_KEYSET;
					case SCARD_W_WRONG_CHV:
						*SubStatus = 0xFFFFFFFF;
						return STATUS_SMARTCARD_WRONG_PIN;
					case SCARD_W_CHV_BLOCKED:
						return STATUS_SMARTCARD_CARD_BLOCKED;
					default:
						return STATUS_LOGON_FAILURE;
				}
				
			}
			EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"RetrieveStoredCredential OK");

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
			Status = UserNameToProfile(*AccountName,(PLSA_DISPATCH_TABLE)MyLsaDispatchTable,
						ClientRequest,(PEID_INTERACTIVE_PROFILE*)ProfileBuffer,ProfileBufferLength);
			EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"ProfileBuffer OK Status = %d",Status);

			// create primary credentials
			PSID pSid = MyTokenInformation->User.User.Sid;
			Status = CompletePrimaryCredential(*AuthenticatingAuthority,*AccountName,pSid,LogonId,szPassword,PrimaryCredentials);
			EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"CompletePrimaryCredential OK Status = %d",Status);
			*SupplementalCredentials = (PSECPKG_SUPPLEMENTAL_CRED_ARRAY) EIDAlloc(sizeof(SECPKG_SUPPLEMENTAL_CRED_ARRAY));
			if (*SupplementalCredentials)
			{
				(*SupplementalCredentials)->CredentialCount = 0;
			}
			if (szPassword)
			{
				SecureZeroMemory(szPassword, wcslen(szPassword) * sizeof(WCHAR));
				EIDFree(szPassword);
			}
			Status = STATUS_SUCCESS;

			EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Success !!");
			return Status;
		}
		__except(EIDExceptionHandler(GetExceptionInformation()))
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"NT exception 0x%08x",GetExceptionCode());
			return STATUS_LOGON_FAILURE;
		}
	}

	void initializeLSAExportedFunctionsTable(PSECPKG_FUNCTION_TABLE exportedFunctions)
	{

		exportedFunctions->InitializePackage = LsaApInitializePackage;
		// missing the word NTAPI in NTSecPkg.h
		exportedFunctions->LogonUserEx2 = (PLSA_AP_LOGON_USER_EX2) LsaApLogonUserEx2;
		exportedFunctions->LogonTerminated = LsaApLogonTerminated;
		exportedFunctions->CallPackage = LsaApCallPackage;
		exportedFunctions->CallPackagePassthrough = LsaApCallPackagePassthrough;
		exportedFunctions->CallPackageUntrusted = LsaApCallPackageUntrusted;
	}

}