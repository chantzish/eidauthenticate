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

#include <ntstatus.h>
#define WIN32_NO_STATUS 1

#include <windows.h>
#include <tchar.h>
#include <Ntsecapi.h>
#define SECURITY_WIN32
#include <sspi.h>
#include <Sddl.h>
#include <ntsecpkg.h>
#include <WinCred.h>
#include <Lm.h>
#include <list>

#include "../EIDCardLibrary/EIDCardLibrary.h"
#include "../EIDCardLibrary/Tracing.h"
#include "../EIDCardLibrary/CredentialManagement.h"
#include "../EIDCardLibrary/CompleteToken.h"

extern "C"
{
	// Save LsaDispatchTable
	PLSA_SECPKG_FUNCTION_TABLE MyLsaDispatchTable;
	PSECPKG_PARAMETERS MyParameters;
	SECPKG_FUNCTION_TABLE MyExportedFunctions;
	ULONG MyExportedFunctionsCount = 1;
	BOOL DoUnicode = TRUE; 
	LUID PackageUid;
	void initializeExportedFunctionsTable(PSECPKG_FUNCTION_TABLE exportedFunctions);

	TimeStamp Forever = {0x7fffffff,0xfffffff};
	TimeStamp Never = {0,0};

	/** The SpLsaModeInitialize function is called once by the  LSA for each registered  
	security support provider/ authentication package (SSP/AP) DLL it loads. This function 
	provides the LSA with pointers to the functions implemented by each  security package 
	in the SSP/AP DLL.*/

	NTSTATUS NTAPI SpLsaModeInitialize(
	  __in   ULONG LsaVersion,
	  __out  PULONG PackageVersionOut,
	  __out  PSECPKG_FUNCTION_TABLE *ppTables,
	  __out  PULONG pcTables
	  )
	{
		EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Enter");
		NTSTATUS Status = STATUS_INVALID_PARAMETER;
		__try
		{
			if (LsaVersion != SECPKG_INTERFACE_VERSION) 
			{
				EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"LsaVersion = %d",LsaVersion);
				__leave;
			}
			*PackageVersionOut = 1;
			memset(&MyExportedFunctions, 0, sizeof(SECPKG_FUNCTION_TABLE));
			initializeExportedFunctionsTable(&MyExportedFunctions);
			*ppTables = &MyExportedFunctions;
			*pcTables = MyExportedFunctionsCount;
			Status = STATUS_SUCCESS;
		}
		__finally
		{
		}
		EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Leave");
		return Status;
	}

	/** The SpInitialize function is called once by the  LSA to provide a  security package
	with general security information and a dispatch table of support functions. The security
	package should save the information and do internal initialization processing, if any is needed.*/
	NTSTATUS NTAPI SpInitialize(
		  __in  ULONG_PTR PackageId,
		  __in  PSECPKG_PARAMETERS Parameters,
		  __in  PLSA_SECPKG_FUNCTION_TABLE FunctionTable
		)
	{
		UNREFERENCED_PARAMETER(PackageId);
		MyParameters = Parameters;
		MyLsaDispatchTable = FunctionTable;
		AllocateLocallyUniqueId(&PackageUid);
		EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Leave");
		return STATUS_SUCCESS;
	}

	/** The SpShutDown function is called by the  LSA before the  security support 
	provider/ authentication package (SSP/AP) is unloaded. The implementation of 
	this function should release any allocated resources, such as  credentials.*/
	NTSTATUS NTAPI SpShutDown()
	{
		EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Leave");
		return STATUS_SUCCESS;
	}

	/**The SpGetInfo function provides general information about the  security package, such as
		its name and capabilities.
		The SpGetInfo function is called when the client calls the QuerySecurityPackageInfo 
		function of the Security Support Provider Interface. */
	NTSTATUS NTAPI SpGetInfo(
		__out  PSecPkgInfo PackageInfo
	)
	{
		PackageInfo->fCapabilities = SECPKG_FLAG_LOGON;
		PackageInfo->wVersion = SECURITY_SUPPORT_PROVIDER_INTERFACE_VERSION;
		PackageInfo->wRPCID = SECPKG_ID_NONE;
		PackageInfo->cbMaxToken = 5000;
		PackageInfo->Name = AUTHENTICATIONPACKAGENAMET;
		PackageInfo->Comment = AUTHENTICATIONPACKAGENAMET;
		EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Leave");
		return STATUS_SUCCESS;
	}

	/** The SpGetExtendedInformation function provides extended information about a  security package. */
	NTSTATUS NTAPI SpGetExtendedInformation(
		  __in   SECPKG_EXTENDED_INFORMATION_CLASS Class,
		  __out  PSECPKG_EXTENDED_INFORMATION *ppInformation
		)
	{
		EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Enter Class = %d",Class);
		UNREFERENCED_PARAMETER(ppInformation);
		NTSTATUS Status = SEC_E_UNSUPPORTED_FUNCTION;
		switch(Class)
		{
			case SecpkgGssInfo:
				Status = SEC_E_UNSUPPORTED_FUNCTION ; 
				break;
			case SecpkgContextThunks:
				Status = SEC_E_UNSUPPORTED_FUNCTION ; 
				break;
			case SecpkgMutualAuthLevel:
				Status = SEC_E_UNSUPPORTED_FUNCTION ; 
				break;
		}
		EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Leave");
		return Status;
	}

	/** The SpSetExtendedInformation function is used to set extended information about the  security package.*/
	NTSTATUS NTAPI SpSetExtendedInformation(
		  __in  SECPKG_EXTENDED_INFORMATION_CLASS Class,
		  __in  PSECPKG_EXTENDED_INFORMATION Info
		)
	{
		EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Enter Class = %d",Class);
		UNREFERENCED_PARAMETER(Info);
		NTSTATUS Status = SEC_E_UNSUPPORTED_FUNCTION;
		switch(Class)
		{
			case SecpkgGssInfo:
				Status = SEC_E_UNSUPPORTED_FUNCTION ; 
				break;
			case SecpkgContextThunks:
				Status = SEC_E_UNSUPPORTED_FUNCTION ; 
				break;
			case SecpkgMutualAuthLevel:
				Status = SEC_E_UNSUPPORTED_FUNCTION ; 
				break;
		}
		EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Leave");
		return Status;
	}

	/** The SpGetUserInfo function retrieves information about a logon  session.*/
	NTSTATUS NTAPI SpGetUserInfo( 
		IN PLUID LogonId, 
		IN ULONG Flags, 
		OUT PSecurityUserData * UserData 
		) 
	{ 
	 
		UNREFERENCED_PARAMETER(LogonId); 
		UNREFERENCED_PARAMETER(Flags); 
		UNREFERENCED_PARAMETER(UserData); 
		EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Enter");
		return(STATUS_NOT_SUPPORTED); 
	} 

	//////////////////////////////////////////////////////////////////////////////////////
	// Credential management
	//////////////////////////////////////////////////////////////////////////////////////

	/** Applies a control token to a  security context. This function is not currently called 
	by the  Local Security Authority (LSA).*/
	NTSTATUS NTAPI SpApplyControlToken(
		LSA_SEC_HANDLE              phContext,          // Context to modify
		PSecBufferDesc              pInput              // Input token to apply
		)
	{
		UNREFERENCED_PARAMETER(phContext);
		UNREFERENCED_PARAMETER(pInput);
		return(STATUS_SUCCESS);

	}

	/** Called by the  Local Security Authority (LSA) to pass the  security package any  
	credentials stored for the authenticated  security principal. This function is called
	once for each set of credentials stored by the LSA.*/
	NTSTATUS NTAPI SpAcceptCredentials(
		  __in  SECURITY_LOGON_TYPE LogonType,
		  __in  PUNICODE_STRING AccountName,
		  __in  PSECPKG_PRIMARY_CRED PrimaryCredentials,
		  __in  PSECPKG_SUPPLEMENTAL_CRED SupplementalCredentials
		)
	{
		EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Enter for account name = %wZ type=%d",AccountName, LogonType);
		UNREFERENCED_PARAMETER(PrimaryCredentials);
		UNREFERENCED_PARAMETER(SupplementalCredentials);
		return STATUS_SUCCESS;
	}

	/** Called to obtain a handle to a principal's  credentials. The  security package can 
	deny access to the caller if the caller does not have permission to access the credentials.

	If the credentials handle is returned to the caller, the package should also specify an expiration time for the handle.*/
	NTSTATUS NTAPI SpAcquireCredentialsHandle(
		  __in   PUNICODE_STRING PrincipalName,
		  __in   ULONG CredentialUseFlags,
		  __in   PLUID LogonId,
		  __in   PVOID AuthorizationData,
		  __in   PVOID GetKeyFunction,
		  __in   PVOID GetKeyArgument,
		  __out  PLSA_SEC_HANDLE CredentialHandle,
		  __out  PTimeStamp ExpirationTime
		)
	{
		UNREFERENCED_PARAMETER(LogonId);
		EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Enter PrincipalName = %wZ",PrincipalName);
		PSEC_WINNT_AUTH_IDENTITY_EXW pAuthIdentityEx = NULL;
		PSEC_WINNT_AUTH_IDENTITY pAuthIdentity = NULL; 
		CCredential* pCredential;
		ULONG CredSize = 0; 
		ULONG Offset = 0; 
		NTSTATUS Status = STATUS_SUCCESS;
		PCERT_CREDENTIAL_INFO pCertInfo = NULL;
		CRED_MARSHAL_TYPE CredType;
		PVOID szCredential = NULL;
		PVOID szPassword = NULL;
		PWSTR szPasswordW = NULL;
		DWORD dwCharSize = 0;
		BOOL UseUnicode = TRUE;
		SECPKG_CLIENT_INFO ClientInfo; 
		PLUID LogonIdToUse; 
		__try
		{
			if ((CredentialUseFlags & (SECPKG_CRED_BOTH)) == 0)
			{
				EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"flag not ok");
				Status = SEC_E_UNKNOWN_CREDENTIALS;
				__leave;
			}
			if (GetKeyFunction)
			{
				EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"GetKeyFunction not ok");
				Status = SEC_E_UNSUPPORTED_FUNCTION;
				__leave;
			}
			if (GetKeyArgument)
			{
				EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"GetKeyArgument not ok");
				Status = SEC_E_UNSUPPORTED_FUNCTION;
				__leave;
			}
				// 
			// First get information about the caller. 
			// 	 
			Status = MyLsaDispatchTable->GetClientInfo(&ClientInfo); 
			if (Status != STATUS_SUCCESS) 
			{ 
				EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"GetKeyArgument not ok 0x%08x", Status); 
				__leave;
			} 
	 
			// 
			// If the caller supplied a logon ID, and it doesn't match the caller, 
			// they must have the TCB privilege 
			// 
		 
			if (LogonId && 
				((LogonId->LowPart != 0) || (LogonId->HighPart != 0)) && 
				!(( LogonId->HighPart == ClientInfo.LogonId.HighPart) && ( LogonId->LowPart == ClientInfo.LogonId.LowPart))) 
				 
			{ 
				if (!ClientInfo.HasTcbPrivilege) 
				{ 
					Status = STATUS_PRIVILEGE_NOT_HELD; 
					__leave;
				} 
				LogonIdToUse = LogonId; 
			} 
			else 
			{ 
				LogonIdToUse = &ClientInfo.LogonId; 
			}
			
			if (AuthorizationData != NULL) 
			{ 
				// copy the authorization data to our user space
				pAuthIdentityEx = (PSEC_WINNT_AUTH_IDENTITY_EXW)
												MyLsaDispatchTable->AllocateLsaHeap(sizeof(SEC_WINNT_AUTH_IDENTITY_EXW)); 
				if (!pAuthIdentityEx) 
				{ 
					Status = STATUS_INSUFFICIENT_RESOURCES; 
					EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"AllocateLsaHeap is 0x%08x", Status); 
					__leave;
				}
				Status = MyLsaDispatchTable->CopyFromClientBuffer( 
							NULL, 
							sizeof(SEC_WINNT_AUTH_IDENTITY), 
							pAuthIdentityEx, 
							AuthorizationData);

				if (Status != STATUS_SUCCESS) 
				{ 
					EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"CopyFromClientBuffer is 0x%08x", Status); 
					__leave;
				} 
				// 
				// Check for the ex version 
				// 
		 
				if (pAuthIdentityEx->Version == SEC_WINNT_AUTH_IDENTITY_VERSION) 
				{ 
					Status = MyLsaDispatchTable->CopyFromClientBuffer( 
								NULL, 
								sizeof(SEC_WINNT_AUTH_IDENTITY_EXW), 
								pAuthIdentityEx, 
								AuthorizationData); 
		 
					if (Status != STATUS_SUCCESS) 
					{ 
						EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"CopyFromClientBuffer is 0x%08x", Status); 
						__leave;
					} 
					pAuthIdentity = (PSEC_WINNT_AUTH_IDENTITY) &pAuthIdentityEx->User; 
					CredSize = pAuthIdentityEx->Length; 
					Offset = FIELD_OFFSET(SEC_WINNT_AUTH_IDENTITY_EXW, User); 
				} 
				else 
				{ 
					pAuthIdentity = (PSEC_WINNT_AUTH_IDENTITY_W) pAuthIdentityEx; 
					CredSize = sizeof(SEC_WINNT_AUTH_IDENTITY_W); 
				} 
		 
				if (pAuthIdentity->Flags & SEC_WINNT_AUTH_IDENTITY_ANSI) 
				{ 
					dwCharSize = sizeof(CHAR);
					UseUnicode = FALSE;
				} 
				else if (pAuthIdentity->Flags & SEC_WINNT_AUTH_IDENTITY_UNICODE)
				{
					dwCharSize = sizeof(WCHAR);
					UseUnicode = TRUE;
				}
				else
				{
					Status = SEC_E_INVALID_TOKEN; 
					EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"pAuthIdentity->Flags is 0x%lx", pAuthIdentity->Flags); 
					__leave;
				}
				szCredential = MyLsaDispatchTable->AllocateLsaHeap((pAuthIdentity->UserLength + 1) * dwCharSize);
				if (!szCredential)
				{
					Status = STATUS_INSUFFICIENT_RESOURCES; 
					EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"AllocateLsaHeap"); 
					__leave;
				}
				Status = MyLsaDispatchTable->CopyFromClientBuffer(NULL, 
															(pAuthIdentity->UserLength + 1) * dwCharSize, 
															szCredential,
															pAuthIdentity->User); 
				if (Status != STATUS_SUCCESS) 
				{ 
					EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"CopyFromClientBuffer is 0x%08x", Status); 
					__leave;
				} 
				BOOL fRes;
				if (UseUnicode)
				{
					fRes = CredUnmarshalCredentialW((LPCWSTR)szCredential,&CredType, (PVOID*) &pCertInfo);
				}
				else
				{
					fRes = CredUnmarshalCredentialA((LPCSTR)szCredential,&CredType, (PVOID*) &pCertInfo);
				}
				if (!fRes) 
				{ 
					EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"CredUnmarshalCredential is 0x%08x UseUnicode=%d", GetLastError(), UseUnicode); 
					Status = SEC_E_UNKNOWN_CREDENTIALS;
					__leave;
				}				
				if (CredType != CertCredential)
				{
					Status = SEC_E_UNKNOWN_CREDENTIALS; 
					EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"CredType is 0x%lx", CredType); 
					__leave;
				}
				szPassword = MyLsaDispatchTable->AllocateLsaHeap((pAuthIdentity->PasswordLength + 1) * dwCharSize);
				if (!szPassword)
				{
					Status = STATUS_INSUFFICIENT_RESOURCES; 
					EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"AllocateLsaHeap"); 
					__leave;
				}
				Status = MyLsaDispatchTable->CopyFromClientBuffer(NULL, 
															(pAuthIdentity->PasswordLength + 1) * dwCharSize, 
															szPassword,
															pAuthIdentity->Password); 
				if (Status != STATUS_SUCCESS) 
				{ 
					EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"CopyFromClientBuffer is 0x%08x", Status); 
					__leave;
				}
				// convert to unicode
				if (UseUnicode)
				{
					szPasswordW = (PWSTR) szPassword;
					szPassword = NULL;
				}
				else
				{
					szPasswordW = (PWSTR) MyLsaDispatchTable->AllocateLsaHeap((pAuthIdentity->PasswordLength + 1) * sizeof(WCHAR));
					if (!szPasswordW)
					{
						Status = STATUS_INSUFFICIENT_RESOURCES; 
						EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"AllocateLsaHeap"); 
						__leave;
					}
					MultiByteToWideChar(CP_ACP, 0, (PSTR) szPassword, -1, szPasswordW, pAuthIdentity->PasswordLength + 1);
				}
			}
			pCredential = CCredential::CreateCredential(LogonIdToUse,pCertInfo, szPasswordW, CredentialUseFlags);
			if (!pCredential)
			{
				EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"AllocateLsaHeap"); 
					__leave;
			}
			*CredentialHandle = (LSA_SEC_HANDLE) pCredential;
			*ExpirationTime = Forever;
		}
		__finally
		{
			if (pCertInfo)
				CredFree(pCertInfo);
			if (szCredential)
				MyLsaDispatchTable->FreeLsaHeap(szCredential);
			if (szPasswordW)
			{
				SecureZeroMemory(szPasswordW,(pAuthIdentity->PasswordLength + 1) * sizeof(WCHAR));
				MyLsaDispatchTable->FreeLsaHeap(szPasswordW);
			}
			if (szPassword)
			{
				SecureZeroMemory(szPassword,(pAuthIdentity->PasswordLength + 1) * dwCharSize);
				MyLsaDispatchTable->FreeLsaHeap(szPassword);
			}
			if (pAuthIdentityEx)
				MyLsaDispatchTable->FreeLsaHeap(pAuthIdentityEx);
		}
			

		return Status;
	}

	/** Frees  credentials acquired by calling the  SpAcquireCredentialsHandle function.*/
	NTSTATUS NTAPI SpFreeCredentialsHandle(
		__in LSA_SEC_HANDLE                 CredentialHandle        // Handle to free
    )
	{
		EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Credential %d",CredentialHandle);
		if (!CCredential::Delete(CredentialHandle))
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Credential %d not found",CredentialHandle);
			return(STATUS_INVALID_HANDLE);
		}
		return(STATUS_SUCCESS);
	}

	/** Used to add  credentials for a  security principal.*/
	NTSTATUS NTAPI SpAddCredentials(
		  __in   LSA_SEC_HANDLE CredentialHandle,
		  __in   PUNICODE_STRING PrincipalName,
		  __in   PUNICODE_STRING Package,
		  __in   ULONG CredentialUseFlags,
		  __in   PVOID AuthorizationData,
		  __in   PVOID GetKeyFunction,
		  __in   PVOID GetKeyArgument,
		  __out  PTimeStamp ExpirationTime
		)
	{
		EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Enter for account name = %wZ package=%wZ",PrincipalName, Package);
		UNREFERENCED_PARAMETER(CredentialHandle);
		UNREFERENCED_PARAMETER(CredentialUseFlags);
		UNREFERENCED_PARAMETER(AuthorizationData);
		UNREFERENCED_PARAMETER(GetKeyFunction);
		UNREFERENCED_PARAMETER(GetKeyArgument);
		// forever
		*ExpirationTime = Forever;
		return STATUS_SUCCESS;
	}

	/** Deletes  credentials from a  security package's list of  primary or  supplemental credentials.*/
	NTSTATUS NTAPI SpDeleteCredentials(
		  __in  LSA_SEC_HANDLE CredentialHandle,
		  __in  PSecBuffer Key
		)
	{
		UNREFERENCED_PARAMETER(Key);
		UNREFERENCED_PARAMETER(CredentialHandle);
		EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Enter");
		return STATUS_SUCCESS;
	}

	/** Saves a  supplemental credential to the user object.*/
	NTSTATUS NTAPI SpSaveCredentials (
		  __in  LSA_SEC_HANDLE CredentialHandle,
		  __in  PSecBuffer Key
		)
	{
		EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Enter");
		UNREFERENCED_PARAMETER(CredentialHandle);
		UNREFERENCED_PARAMETER(Key);
		return STATUS_SUCCESS;
	}
	
	/** The SpGetCredentials function retrieves the  primary and  supplemental credentials from the user object.*/
	NTSTATUS NTAPI SpGetCredentials (
		  __in  LSA_SEC_HANDLE CredentialHandle,
		  __out  PSecBuffer Credentials
		)
	{
		EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Enter");
		UNREFERENCED_PARAMETER(CredentialHandle);
		UNREFERENCED_PARAMETER(Credentials);
		return STATUS_NOT_IMPLEMENTED;
	}

		/** The SpQueryCredentialsAttributes function retrieves the attributes for a  credential.

	The SpQueryCredentialsAttributes function is the dispatch function for the 
	QueryCredentialsAttributes function of the Security Support Provider Interface.*/
	NTSTATUS NTAPI SpQueryCredentialsAttributes(
		  __in   LSA_SEC_HANDLE CredentialHandle,
		  __in   ULONG CredentialAttribute,
		  __out  PVOID Buffer
		)
	{
		EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Enter CredentialAttribute = %d",CredentialAttribute);
		NTSTATUS status = STATUS_SUCCESS;
		PTSTR szName;
		DWORD dwSize;
		CCredential* pCredential = CCredential::GetCredentialFromHandle(CredentialHandle);
		if (!pCredential)
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"CredentialHandle = %d : STATUS_INVALID_HANDLE",CredentialHandle);
			return STATUS_INVALID_HANDLE;
		}
		switch(CredentialAttribute)
		{
			case SECPKG_CRED_ATTR_NAMES:
				__try
				{
					szName = pCredential->GetName();
					if (!szName)
					{
						EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"szName NULL");
						status = SEC_E_INSUFFICIENT_MEMORY;
						__leave;
					}
					dwSize = (_tcslen(szName)+1) * sizeof(TCHAR);
					status = MyLsaDispatchTable->AllocateClientBuffer(NULL, dwSize, (PVOID*) Buffer);
					if (status != STATUS_SUCCESS)
					{
						EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"AllocateClientBuffer status = 0x%08x",status);
						__leave;
					}
					status = MyLsaDispatchTable->CopyToClientBuffer(NULL, dwSize, *((PVOID*) Buffer), szName);
					if (status != STATUS_SUCCESS)
					{
						EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"CopyToClientBuffer status = 0x%08x",status);
						__leave;
					}
					status = STATUS_SUCCESS;
				}
				__finally
				{	
				}
				EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"SECPKG_CRED_ATTR_NAMES status = 0x%08x",status);
				return status;
				break;
			default:
				return STATUS_INVALID_PARAMETER_2;
		}
	}

	

	//////////////////////////////////////////////////////////////////////////////////////
	// Context management
	//////////////////////////////////////////////////////////////////////////////////////

	
	/** Deletes a  security context.*/
	NTSTATUS NTAPI SpDeleteSecurityContext(
		__in LSA_SEC_HANDLE                 phContext           // Context to delete
    )
	{
		EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Handle %d",phContext);
		if (!CSecurityContext::Delete(phContext))
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Handle %d not found",phContext);
			return(SEC_E_INVALID_HANDLE);
		}
		return(SEC_E_OK);
	}

	/**  The SpQueryContextAttributes function retrieves the attributes of a  security context.

	The SpQueryContextAttributes function is the dispatch function for the 
	QueryContextAttributes (General) function of the Security Support Provider Interface.*/
	NTSTATUS NTAPI SpQueryContextAttributes(
		  __in   LSA_SEC_HANDLE ContextHandle,
		  __in   ULONG ContextAttribute,
		  __out  PVOID pBuffer
		)
	{
		EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Enter");
		CSecurityContext* pContext = CSecurityContext::GetContextFromHandle(ContextHandle);
		if (!ContextHandle)
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"ContextHandle = %d",ContextHandle);
			return STATUS_INVALID_HANDLE;
		}
		PSecPkgContext_Sizes ContextSizes;
		PSecPkgContext_NamesW ContextNames;
		PSecPkgContext_Lifespan ContextLifespan;
		PSecPkgContext_DceInfo  ContextDceInfo;
		switch(ContextAttribute) {
			case SECPKG_ATTR_SIZES:
				ContextSizes = (PSecPkgContext_Sizes) pBuffer;
				ContextSizes->cbMaxSignature = 0;
				ContextSizes->cbSecurityTrailer = 0;
				ContextSizes->cbBlockSize = 0;
				ContextSizes->cbMaxToken = 0;
				break;
			case SECPKG_ATTR_NAMES:
				ContextNames = (PSecPkgContext_Names) pBuffer;
				ContextNames->sUserName = (LPWSTR) EIDAlloc( sizeof(L"dummy user"));
				if (ContextNames->sUserName == NULL)
				{
					return(SEC_E_INSUFFICIENT_MEMORY);
				}
				RtlCopyMemory(ContextNames->sUserName, L"dummy user", sizeof(L"dummy user"));
				break;
			case SECPKG_ATTR_LIFESPAN:
				ContextLifespan = (PSecPkgContext_Lifespan) pBuffer;
				ContextLifespan->tsStart = Never;
				ContextLifespan->tsExpiry = Forever;
				break;
			case SECPKG_ATTR_DCE_INFO:
				ContextDceInfo = (PSecPkgContext_DceInfo) pBuffer;
				ContextDceInfo->AuthzSvc = 0;
				ContextDceInfo->pPac = (PVOID) EIDAlloc(sizeof(L"dummy user"));
				if (ContextDceInfo->pPac == NULL)
				{
					return(SEC_E_INSUFFICIENT_MEMORY);
				}
				RtlCopyMemory((LPWSTR) ContextDceInfo->pPac, L"dummy user", sizeof(L"dummy user"));

				break;
			default:
				return(SEC_E_INVALID_TOKEN);
			}

			return(SEC_E_OK);
	}



	/**  The SpInitLsaModeContext function is the client dispatch function used to establish a 
	security context between a server and client.

	The SpInitLsaModeContext function is called when the client calls the 
	InitializeSecurityContext (General) function of the Security Support Provider Interface.*/
	NTSTATUS NTAPI SpInitLsaModeContext(
		  __in   LSA_SEC_HANDLE CredentialHandle,
		  __in   LSA_SEC_HANDLE ContextHandle,
		  __in   PUNICODE_STRING TargetName,
		  __in   ULONG ContextRequirements,
		  __in   ULONG TargetDataRep,
		  __in   PSecBufferDesc InputBuffers,
		  __out  PLSA_SEC_HANDLE NewContextHandle,
		  __out  PSecBufferDesc OutputBuffers,
		  __out  PULONG ContextAttributes,
		  __out  PTimeStamp ExpirationTime,
		  __out  PBOOLEAN MappedContext,
		  __out  PSecBuffer ContextData
		)
	{
		UNREFERENCED_PARAMETER(ContextData);
		UNREFERENCED_PARAMETER(TargetDataRep);
		UNREFERENCED_PARAMETER(ContextRequirements);
		EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Enter TargetName = %wZ",TargetName);
		NTSTATUS Status = STATUS_SUCCESS;
		__try
		{
			CSecurityContext* newContext = NULL;
			*MappedContext = FALSE;
			*ContextAttributes = ASC_REQ_CONNECTION | ASC_REQ_REPLAY_DETECT;
			if (ContextHandle == NULL)
			{
				// locate credential
				CCredential* pCredential = CCredential::GetCredentialFromHandle(CredentialHandle);
				if (pCredential == NULL)
				{
					EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"pCredential = %d",pCredential);
					Status = SEC_E_UNKNOWN_CREDENTIALS;
					__leave;
				}
				if ((pCredential->Use & SECPKG_CRED_INBOUND) == 0)
				{
					EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Use = %d",pCredential->Use);
					Status = SEC_E_UNKNOWN_CREDENTIALS;
					__leave;
				}
				// create new context : first message
				newContext = CSecurityContext::CreateContext(pCredential);
				*NewContextHandle = (LSA_SEC_HANDLE) newContext;
			}
			else
			{
				// retrieve previous context
				CSecurityContext* currentContext = CSecurityContext::GetContextFromHandle(ContextHandle);
				if (currentContext == NULL)
				{
					EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"currentContext = %d",currentContext);
					Status = SEC_E_INVALID_HANDLE;
					__leave;
				}
				*NewContextHandle = ContextHandle;
				newContext = currentContext;
				Status = currentContext->InitializeSecurityContextInput(InputBuffers);
				if (Status != STATUS_SUCCESS)
				{
					EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"InitializeSecurityContextInput = 0x%08X",Status);
					__leave;
				}
			}
			// forever
			*ExpirationTime = Forever;
			Status = newContext->InitializeSecurityContextOutput(OutputBuffers);
			if (Status != STATUS_SUCCESS)
			{
				EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"InitializeSecurityContextOutput = 0x%08X",Status);
				__leave;
			}
			
		}
		__finally
		{
		}
		EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Status = 0x%08X",Status);
		return Status;
	}

	NTSTATUS NTAPI SpCreateToken(DWORD dwRid, PHANDLE phToken)
	{
		NTSTATUS Status = STATUS_SUCCESS, SubStatus;
		PLUID LogonId = NULL;
		TOKEN_GROUPS tokenGroups = { 0};
		TOKEN_SOURCE tokenSource = { "EIDAuth", PackageUid};
		UNICODE_STRING AccountName;
		UNICODE_STRING AuthorityName;
		UNICODE_STRING Workstation;
		UNICODE_STRING ProfilePath;
		PLSA_TOKEN_INFORMATION_V2 MyTokenInformation = NULL;
		DWORD TokenLength;
		WCHAR szComputer[256];
		WCHAR szUserName[256];
		WCHAR szDomaineName[256];
		DWORD dwSize;
		USER_INFO_3 *pInfo = NULL;
		DWORD dwEntriesRead, dwTotalEntries;
		NET_API_STATUS NetStatus ;
		DWORD dwI;
		__try
		{
			// create session
			if (!phToken)
			{
				EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"phToken null");
				Status = STATUS_INVALID_PARAMETER;
			}
			*phToken = INVALID_HANDLE_VALUE;
			// create the sid from the rid
			
			NetStatus = NetUserEnum(NULL, 3, 0, (PBYTE*)&pInfo, MAX_PREFERRED_LENGTH, &dwEntriesRead,&dwTotalEntries, NULL);
			if (NetStatus != NERR_Success)
			{
				EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"NetUserEnum = 0x%08X",NetStatus);
				__leave;
			}
			for (dwI = 0; dwI < dwEntriesRead; dwI++)
			{
				if ( pInfo[dwI].usri3_user_id == dwRid)
				{
					wcscpy_s(szUserName, ARRAYSIZE(szUserName), pInfo[dwI].usri3_name);
					break;
				}
			}
			if (dwI >= dwEntriesRead)
			{
				EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Userid not found");
				__leave;
			}
			dwSize = ARRAYSIZE(szComputer);
			GetComputerNameW(szComputer, &dwSize);
			Workstation.Buffer = szComputer;
			AuthorityName.Buffer = szDomaineName;
			Workstation.Length = Workstation.MaximumLength = (USHORT) (wcslen(szComputer) * sizeof(WCHAR));
			AuthorityName.Length = AuthorityName.MaximumLength = (USHORT) (wcslen(szDomaineName) * sizeof(WCHAR));
				
			AccountName.Buffer = szUserName;
			AccountName.Length = AccountName.MaximumLength = (USHORT)(wcslen(szUserName) * sizeof(WCHAR));
			Status = AllocateLocallyUniqueId (LogonId);
			if (Status != STATUS_SUCCESS)
			{
				EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"No Memory logon_id");
				__leave;
			}
			Status = MyLsaDispatchTable->CreateLogonSession(LogonId);
			if (Status != STATUS_SUCCESS)
			{
				EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"CreateLogonSession = 0x%08X",Status);
				__leave;
			}
			EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"TokenInformation ?");
			Status = UserNameToToken(&AccountName,(PLSA_DISPATCH_TABLE)MyLsaDispatchTable,
						&MyTokenInformation,&TokenLength, &SubStatus);
			if (Status != STATUS_SUCCESS) 
			{
				EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"UserNameToToken failed 0x%08X 0x%08X",Status, SubStatus);
				__leave;
			}
			Status = MyLsaDispatchTable->CreateToken(LogonId, &tokenSource, Network, SecurityImpersonation, 
				LsaTokenInformationV2, MyTokenInformation, &tokenGroups, &AccountName, &AuthorityName, &Workstation, &ProfilePath, phToken, &SubStatus);
			if (Status != STATUS_SUCCESS) 
			{
				EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"CreateToken failed 0x%08X 0x%08X",Status, SubStatus);
				__leave;
			}
		}
		__finally
		{
			if (pInfo)
				NetApiBufferFree(pInfo);
			if (MyTokenInformation)
				MyLsaDispatchTable->FreeLsaHeap(MyTokenInformation);
		}
		return Status;
	}

	/** Server dispatch function used to create a  security context shared by a server and client.

	The SpAcceptLsaModeContext function is called when the server calls the 
	AcceptSecurityContext (General) function of the Security Support Provider Interface.*/
	NTSTATUS NTAPI SpAcceptLsaModeContext(
		  __in   LSA_SEC_HANDLE CredentialHandle,
		  __in   LSA_SEC_HANDLE ContextHandle,
		  __in   PSecBufferDesc InputBuffers,
		  __in   ULONG ContextRequirements,
		  __in   ULONG TargetDataRep,
		  __out  PLSA_SEC_HANDLE NewContextHandle,
		  __out  PSecBufferDesc OutputBuffers,
		  __out  PULONG ContextAttributes,
		  __out  PTimeStamp ExpirationTime,
		  __out  PBOOLEAN MappedContext,
		  __out  PSecBuffer ContextData
		)
	{
		UNREFERENCED_PARAMETER(ContextData);
		UNREFERENCED_PARAMETER(TargetDataRep);
		UNREFERENCED_PARAMETER(ContextRequirements);
		EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Enter");
		NTSTATUS Status = STATUS_SUCCESS;
		PEID_SSP_CALLBACK_MESSAGE callbackMessage = NULL;
		HANDLE hToken;
		__try
		{
			CSecurityContext* newContext = NULL;
			*MappedContext = FALSE;
			*ContextAttributes = ASC_REQ_CONNECTION | ASC_REQ_REPLAY_DETECT;
			if (ContextHandle == NULL)
			{
				// locate credential
				CCredential* pCredential = CCredential::GetCredentialFromHandle(CredentialHandle);
				if (pCredential == NULL)
				{
					EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"pCredential = %d",pCredential);
					Status = SEC_E_UNKNOWN_CREDENTIALS;
					__leave;
				}
				if ((pCredential->Use & SECPKG_CRED_OUTBOUND) == 0)
				{
					EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Use = %d",pCredential->Use);
					Status = SEC_E_UNKNOWN_CREDENTIALS;
					__leave;
				}
				// create new context : first message
				newContext = CSecurityContext::CreateContext(pCredential);
				*NewContextHandle = (LSA_SEC_HANDLE) newContext;
			}
			else
			{
				// retrieve previous context
				CSecurityContext* currentContext = CSecurityContext::GetContextFromHandle(ContextHandle);
				if (currentContext == NULL)
				{
					EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"currentContext = %d",currentContext);
					Status = SEC_E_INVALID_HANDLE;
					__leave;
				}
				*NewContextHandle = ContextHandle;
				newContext = currentContext;
			}
			Status = newContext->AcceptSecurityContextInput(InputBuffers);
			if (Status != STATUS_SUCCESS)
			{
				EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"AcceptSecurityContextInput = 0x%08X",Status);
				__leave;
			}
			Status = newContext->AcceptSecurityContextOutput(OutputBuffers);
			// forever
			*ExpirationTime = Forever;
			if (Status != STATUS_SUCCESS)
			{
				EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"AcceptSecurityContextOutput = 0x%08X",Status);
				__leave;
			}
			// final call :
			// create a token and send it to the client

			Status = SpCreateToken(newContext->GetRid(), &hToken);
			if (Status != STATUS_SUCCESS)
			{
				EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"SpCreateToken = 0x%08X",Status);
				__leave;
			}
			callbackMessage = (PEID_SSP_CALLBACK_MESSAGE) MyLsaDispatchTable->AllocateLsaHeap(sizeof(EID_SSP_CALLBACK_MESSAGE));
			if (!callbackMessage)
			{
				EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"callbackMessage no memory");
				__leave;
			}
			callbackMessage->Caller = EIDSSPAccept;
			callbackMessage->hToken = hToken;
			*MappedContext = TRUE;
			ContextData->BufferType = SECBUFFER_DATA;
			ContextData->cbBuffer = sizeof(EID_SSP_CALLBACK_MESSAGE);
			ContextData->pvBuffer = callbackMessage;
			
		}
		__finally
		{
		}
		EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Status = 0x%08X",Status);
		return Status;
	}

	void initializeLSAExportedFunctionsTable(PSECPKG_FUNCTION_TABLE exportedFunctions);
	/** Called during system initialization to permit the authentication package to perform
	initialization tasks.*/
	// at the end to avoid double declaration of functions
	void initializeExportedFunctionsTable(PSECPKG_FUNCTION_TABLE exportedFunctions)
	{
		initializeLSAExportedFunctionsTable(exportedFunctions);
		exportedFunctions->Initialize = SpInitialize;
		exportedFunctions->Shutdown = SpShutDown;
		exportedFunctions->GetInfo = SpGetInfo;
		exportedFunctions->AcceptCredentials = SpAcceptCredentials;
		exportedFunctions->AcquireCredentialsHandle = SpAcquireCredentialsHandle;
		exportedFunctions->QueryCredentialsAttributes = SpQueryCredentialsAttributes;
		exportedFunctions->FreeCredentialsHandle = SpFreeCredentialsHandle;
		exportedFunctions->SaveCredentials = SpSaveCredentials;
		exportedFunctions->GetCredentials = SpGetCredentials;
		exportedFunctions->DeleteCredentials = SpDeleteCredentials;
		exportedFunctions->InitLsaModeContext = SpInitLsaModeContext;
		exportedFunctions->AcceptLsaModeContext = SpAcceptLsaModeContext;
		exportedFunctions->DeleteContext = SpDeleteSecurityContext;
		exportedFunctions->ApplyControlToken = SpApplyControlToken;
		exportedFunctions->GetUserInfo = SpGetUserInfo;
		exportedFunctions->GetExtendedInformation = SpGetExtendedInformation;
		exportedFunctions->QueryContextAttributes = SpQueryContextAttributes;
		exportedFunctions->AddCredentials = SpAddCredentials;
		exportedFunctions->SetExtendedInformation = SpSetExtendedInformation;
		exportedFunctions->SetContextAttributes = NULL; // only schanel implements this
		exportedFunctions->SetCredentialsAttributes = NULL; // not documented
		exportedFunctions->ChangeAccountPassword = NULL; // not documented
	}
}