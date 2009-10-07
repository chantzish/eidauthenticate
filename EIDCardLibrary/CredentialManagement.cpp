#include <ntstatus.h>
#define WIN32_NO_STATUS 1

#include <windows.h>
#include <assert.h>
#define SECURITY_WIN32
#include <sspi.h>
#include <WinCred.h>
#include <Ntsecapi.h>
#include <ntsecpkg.h>
//#include <WinCred.h>
#include <set>
#include <map>
#include "../EIDCardLibrary/EIDCardLibrary.h"
#include "../EIDCardLibrary/Tracing.h"
#include "../EIDCardLibrary/StoredCredentialManagement.h"
#include "../EIDCardLibrary/CertificateUtilities.h"
#include "credentialManagement.h"

#pragma comment(lib,"Winscard")
#pragma comment(lib,"Cryptui")

std::set<CCredential*> Credentials;
std::list<CSecurityContext*> Contexts;
std::map<ULONG_PTR, CUsermodeContext*> UserModeContexts;
typedef std::pair <LUID, CCredential*> Credential_Pair;


CCredential* CCredential::CreateCredential(PLUID LogonIdToUse, PCERT_CREDENTIAL_INFO pCertInfo,PWSTR szPin, ULONG CredentialUseFlags)
{
	CCredential* credential = NULL;

	if (!LogonIdToUse)
	{
		EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"LogonIdToUse NULL");
		return NULL;
	}
	if (pCertInfo)
	{
		credential = new CCredential(LogonIdToUse,pCertInfo,szPin, CredentialUseFlags);
		Credentials.insert(credential);
	}
	else
	{
		// find previous credential
		std::set<CCredential*>::iterator iter;
		for ( iter = Credentials.begin( ); iter != Credentials.end( ); iter++ )
		{
			CCredential* currentCredential = *iter;
			if (currentCredential->Check(LogonIdToUse))
			{
				credential = currentCredential;
				break;
			}
		}
		if (!credential)
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"pCredential NULL");
		}
	}
	return credential;
}

CCredential::CCredential(PLUID LogonIdToUse, PCERT_CREDENTIAL_INFO pCertInfo,PWSTR szPin, ULONG CredentialUseFlags)
{
	_dwLen = wcslen(szPin) + 1;
	_LogonId = *LogonIdToUse;
	for (int i = 0; i < CERT_HASH_LENGTH; i++)
	{
		_rgbHashOfCert[i] = pCertInfo->rgbHashOfCert[i];
	}
	_szPin = new WCHAR[_dwLen];
	wcscpy_s(_szPin,_dwLen, szPin);
	Use = CredentialUseFlags;
	_pCertInfo = (PCERT_CREDENTIAL_INFO) EIDAlloc(pCertInfo->cbSize);
	memcpy(_pCertInfo, pCertInfo, pCertInfo->cbSize);

}

CCredential::~CCredential()
{
	SecureZeroMemory(_szPin, _dwLen * sizeof(WCHAR));
	delete[] _szPin;
	EIDFree(_pCertInfo);
}

BOOL CCredential::Delete(ULONG_PTR phCredential)
{
	CCredential* testedCredential = (CCredential*) phCredential;
	std::set<CCredential*>::iterator iter;
	for ( iter = Credentials.begin( ); iter != Credentials.end( ); iter++ )
	{
		CCredential* currentCredential = *iter;
		if (currentCredential == testedCredential)
		{
			delete testedCredential;
			Credentials.erase(iter);
			return TRUE;
		}
	}
	return FALSE;
}

CCredential* CCredential::GetCredentialFromHandle(ULONG_PTR CredentialHandle)
{
	CCredential* pCredential = (CCredential*) CredentialHandle;
	CCredential* currentCredential = NULL;
	std::set<CCredential*>::iterator iter;
	for ( iter = Credentials.begin( ); iter != Credentials.end( ); iter++ )
	{
		currentCredential = *iter;
		if (currentCredential == pCredential)
		{
			return currentCredential;
		}
	}
	return NULL;
}

PTSTR CCredential::GetName()
{
	return NULL;
}

CSecurityContext* CSecurityContext::CreateContext(CCredential* pCredential)
{
	CSecurityContext* context = NULL;
	if (!pCredential)
	{
		EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"pCredential NULL");
		return NULL;
	}
	context = new CSecurityContext(pCredential);
	Contexts.push_back(context);
	return context;
}


CSecurityContext::CSecurityContext(CCredential* pCredential)
{
	_pCredential = pCredential;
	_State = EIDMSNone;
	pbChallenge = NULL;
	pbResponse = NULL;
	dwChallengeSize = 0;
	dwResponseSize = 0;
	dwRid = 0;
	pCertContext = NULL;
	szPassword = NULL;
	if (pCredential)
	{
		if (pCredential->_pCertInfo)
		{
			CRYPT_DATA_BLOB blob;
			blob.pbData = pCredential->_pCertInfo->rgbHashOfCert;
			blob.cbData = CERT_HASH_LENGTH;
			pCertContext = FindCertificateFromHash(&blob);
		}
	}
}

BOOL CSecurityContext::Delete(ULONG_PTR phContext)
{
	CSecurityContext* testedContext = (CSecurityContext*) phContext;
	std::list<CSecurityContext*>::iterator iter;
	for ( iter = Contexts.begin( ); iter != Contexts.end( ); iter++ )
	{
		CSecurityContext* currentContext = (CSecurityContext*) *iter;
		if (currentContext == testedContext)
		{
			delete testedContext;
			Contexts.erase(iter);
			
			return TRUE;
		}
	}
	return FALSE;
}

CSecurityContext* CSecurityContext::GetContextFromHandle(ULONG_PTR context)
{
	std::list<CSecurityContext*>::iterator iter;
	CSecurityContext* testedContext = (CSecurityContext*) context;
	for ( iter = Contexts.begin( ); iter != Contexts.end( ); iter++ )
	{
		CSecurityContext* currentContext = (CSecurityContext*) *iter;
		if (currentContext == testedContext)
		{
			return currentContext;
		}
	}
	return NULL;
}

NTSTATUS CSecurityContext::InitializeSecurityContextInput(PSecBufferDesc Buffer)
{
	NTSTATUS Status = STATUS_INVALID_SIGNATURE;
	switch (_State)
	{
		case EIDMSNegociate:
			Status = ReceiveChallengeMessage(Buffer);
			break;
	}
	EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Status = 0x%08X", Status);
	return Status;
}
NTSTATUS CSecurityContext::InitializeSecurityContextOutput(PSecBufferDesc Buffer)
{
	NTSTATUS Status = STATUS_INVALID_SIGNATURE;
	switch (_State)
	{
		case EIDMSNone:
			Status = BuildNegociateMessage(Buffer);
			break;
		case EIDMSChallenge:
			Status = BuildResponseMessage(Buffer);
			break;
	}
	EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Status = 0x%08X", Status);
	return Status;
}
NTSTATUS CSecurityContext::AcceptSecurityContextInput(PSecBufferDesc Buffer)
{
	NTSTATUS Status = STATUS_INVALID_SIGNATURE;
	switch (_State)
	{
		case EIDMSNone:
			Status = ReceiveNegociateMessage(Buffer);
			break;
		case EIDMSChallenge:
			Status = ReceiveResponseMessage(Buffer);
			break;
	}
	EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Status = 0x%08X", Status);
	return Status;
}
NTSTATUS CSecurityContext::AcceptSecurityContextOutput(PSecBufferDesc Buffer)
{
	NTSTATUS Status = STATUS_INVALID_SIGNATURE;
	switch (_State)
	{
		case EIDMSNegociate:
			Status = BuildChallengeMessage(Buffer);
			break;
		case EIDMSComplete:
			Status = BuildCompleteMessage(Buffer);
			break;
	}
	EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Status = 0x%08X", Status);
	return Status;
}

NTSTATUS CSecurityContext::BuildNegociateMessage(PSecBufferDesc Buffer)
{
	Buffer->pBuffers[0].BufferType = SECBUFFER_TOKEN;
	if (Buffer->pBuffers[0].cbBuffer < 300)
	{
		return SEC_E_INSUFFICIENT_MEMORY;
	}
	PEID_NEGOCIATE_MESSAGE message = (PEID_NEGOCIATE_MESSAGE) Buffer->pBuffers[0].pvBuffer;
	memset(message, 0, sizeof(EID_NEGOCIATE_MESSAGE));
	memcpy(message->Signature, EID_MESSAGE_SIGNATURE, 8);
	message->MessageType = EIDMTNegociate;
	message->Version = EID_MESSAGE_VERSION;
	memcpy(Hash, _pCredential->_rgbHashOfCert, CERT_HASH_LENGTH);
	memcpy(message->Hash, _pCredential->_rgbHashOfCert, CERT_HASH_LENGTH);
	_State = EIDMSNegociate;
	return SEC_I_CONTINUE_NEEDED;
}

NTSTATUS CSecurityContext::ReceiveNegociateMessage(PSecBufferDesc Buffer)
{
	PEID_NEGOCIATE_MESSAGE message = (PEID_NEGOCIATE_MESSAGE) Buffer->pBuffers[0].pvBuffer;
	if (memcmp(EID_MESSAGE_SIGNATURE,message->Signature, 8) != 0)
	{
		return STATUS_INVALID_SIGNATURE;
	}
	if (message->MessageType != EIDMTNegociate)
	{
		return STATUS_INVALID_SIGNATURE;
	}
	memcpy(Hash, message->Hash, CERT_HASH_LENGTH);
	_State = EIDMSNegociate;
	return STATUS_SUCCESS;
}

NTSTATUS CSecurityContext::BuildChallengeMessage(PSecBufferDesc Buffer)
{
	Buffer->pBuffers[0].BufferType = SECBUFFER_TOKEN;
	if (Buffer->pBuffers[0].cbBuffer < 300)
	{
		return SEC_E_INSUFFICIENT_MEMORY;
	}
	PEID_CHALLENGE_MESSAGE message = (PEID_CHALLENGE_MESSAGE) Buffer->pBuffers[0].pvBuffer;
	memset(message, 0, sizeof(EID_CHALLENGE_MESSAGE));
	memcpy(message->Signature, EID_MESSAGE_SIGNATURE, 8);
	message->MessageType = EIDMTChallenge;
	message->Version = EID_MESSAGE_VERSION;
	CStoredCredentialManager* manager = CStoredCredentialManager::Instance();
	if (!manager->GetCertContextFromHash(Hash, &pCertContext, &dwRid))
	{
		return SEC_E_UNKNOWN_CREDENTIALS;
	}
	if (!manager->GetChallenge(dwRid, &pbChallenge, &dwChallengeSize))
	{
		return SEC_E_INTERNAL_ERROR;
	}
	message->ChallengeLen = dwChallengeSize;
	message->ChallengeOffset = sizeof(EID_CHALLENGE_MESSAGE);
	memcpy((PBYTE)message + message->ChallengeOffset, pbChallenge, dwChallengeSize);
	_State = EIDMSChallenge;
	return SEC_I_CONTINUE_NEEDED;
}

NTSTATUS CSecurityContext::ReceiveChallengeMessage(PSecBufferDesc Buffer)
{
	PEID_CHALLENGE_MESSAGE message = (PEID_CHALLENGE_MESSAGE) Buffer->pBuffers[0].pvBuffer;
	if (memcmp(EID_MESSAGE_SIGNATURE,message->Signature,8) != 0)
	{
		return STATUS_INVALID_SIGNATURE;
	}
	if (message->MessageType != EIDMTChallenge)
	{
		return STATUS_INVALID_SIGNATURE;
	}
	pbChallenge = (PBYTE) EIDAlloc(message->ChallengeLen);
	memcpy(pbChallenge, (PBYTE)message + message->ChallengeOffset, message->ChallengeLen);
	dwChallengeSize = message->ChallengeLen;
	_State = EIDMSChallenge;
	return STATUS_SUCCESS;
}

NTSTATUS CSecurityContext::BuildResponseMessage(PSecBufferDesc Buffer)
{
	Buffer->pBuffers[0].BufferType = SECBUFFER_TOKEN;
	if (Buffer->pBuffers[0].cbBuffer < 300)
	{
		return SEC_E_INSUFFICIENT_MEMORY;
	}
	PEID_RESPONSE_MESSAGE message = (PEID_RESPONSE_MESSAGE) Buffer->pBuffers[0].pvBuffer;
	memset(message, 0, sizeof(EID_RESPONSE_MESSAGE));
	memcpy(message->Signature, EID_MESSAGE_SIGNATURE, 8);
	message->MessageType = EIDMTResponse;
	message->Version = EID_MESSAGE_VERSION;
	CStoredCredentialManager* manager = CStoredCredentialManager::Instance();
	if (!manager->GetResponseFromChallenge(pbChallenge, dwChallengeSize, pCertContext,_pCredential->_szPin, &pbResponse, &dwResponseSize))
	{
		return SEC_E_LOGON_DENIED;
	}
	message->ResponseLen = dwResponseSize;
	message->ResponseOffset = sizeof(EID_RESPONSE_MESSAGE);
	memcpy((PBYTE)message + message->ResponseOffset, pbResponse, dwResponseSize);
	_State = EIDMSComplete;
	return STATUS_SUCCESS;
}

NTSTATUS CSecurityContext::ReceiveResponseMessage(PSecBufferDesc Buffer)
{
	PEID_RESPONSE_MESSAGE message = (PEID_RESPONSE_MESSAGE) Buffer->pBuffers[0].pvBuffer;
	if (memcmp(EID_MESSAGE_SIGNATURE,message->Signature,8) != 0)
	{
		return STATUS_INVALID_SIGNATURE;
	}
	if (message->MessageType != EIDMTResponse)
	{
		return STATUS_INVALID_SIGNATURE;
	}
	pbResponse = (PBYTE) EIDAlloc(message->ResponseLen);
	dwResponseSize = message->ResponseLen;
	memcpy(pbResponse, (PBYTE)message + message->ResponseOffset, dwResponseSize);
	_State = EIDMSComplete;
	return STATUS_SUCCESS;
}

NTSTATUS CSecurityContext::BuildCompleteMessage(PSecBufferDesc Buffer)
{
	// vérification du challenge
	UNREFERENCED_PARAMETER(Buffer);
	CStoredCredentialManager* manager = CStoredCredentialManager::Instance();
	if (!manager->GetPasswordFromChallengeResponse(dwRid, pbResponse, dwResponseSize, &szPassword))
	{
		return SEC_E_LOGON_DENIED;
	}
	return STATUS_SUCCESS;
}

DWORD CSecurityContext::GetRid()
{
	return dwRid;
}

CSecurityContext::~CSecurityContext()
{
	if (pbChallenge)
	{
		SecureZeroMemory(pbChallenge, dwChallengeSize);
		EIDFree(pbChallenge);
	}
	if (pbResponse)
	{
		SecureZeroMemory(pbResponse, dwResponseSize);
		EIDFree(pbResponse);
	}
	if (pCertContext)
	{
		CertFreeCertificateContext(pCertContext);
	}
	if (szPassword)
	{
		SecureZeroMemory(szPassword, wcslen(szPassword) * sizeof(WCHAR));
		EIDFree(szPassword);
	}
}

CUsermodeContext::CUsermodeContext(PEID_SSP_CALLBACK_MESSAGE pMessage)
{
	Handle = pMessage->hToken;
}

NTSTATUS CUsermodeContext::AddContextInfo(ULONG_PTR pHandle, PEID_SSP_CALLBACK_MESSAGE pMessage)
{
	NTSTATUS Status = STATUS_SUCCESS;
	CUsermodeContext* pContext = GetContextFromHandle(pHandle);
	if (!pContext)
	{
		pContext = new CUsermodeContext(pMessage);
		UserModeContexts.insert(std::pair<ULONG_PTR,CUsermodeContext*> (pHandle, pContext));
	}
	return Status ;
}

NTSTATUS CUsermodeContext::DeleteContextInfo(ULONG_PTR pHandle)
{
	std::map<ULONG_PTR, CUsermodeContext*>::iterator it = UserModeContexts.find(pHandle);
	if (it == UserModeContexts.end())
	{
		return SEC_E_INVALID_HANDLE;
	}
	else
	{
		UserModeContexts.erase(it);
		return STATUS_SUCCESS;
	}
}

NTSTATUS CUsermodeContext::GetImpersonationHandle(ULONG_PTR pHandle,PHANDLE ImpersonationToken)
{
	NTSTATUS Status = STATUS_SUCCESS;
	CUsermodeContext* pContext = GetContextFromHandle(pHandle);
	if (!pContext)
	{
		return SEC_E_INVALID_HANDLE;
	}
	*ImpersonationToken = pContext->Handle;
	return Status ;
}

CUsermodeContext* CUsermodeContext::GetContextFromHandle(ULONG_PTR pHandle)
{
	std::map<ULONG_PTR, CUsermodeContext*>::iterator it = UserModeContexts.find(pHandle);
	if (it == UserModeContexts.end())
	{
		EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Context not found = 0x%08X", pHandle);
		return NULL;
	}
	else
	{
		return (*it).second;
	}
}