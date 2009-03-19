
#pragma once

#include <ntsecapi.h>

#define AUTHENTICATIONPACKAGENAME "EIDAuthenticationPackage"
#define AUTHENTICATIONPACKAGENAMEW L"EIDAuthenticationPackage"
#define AUTHENTICATIONPACKAGENAMET TEXT("EIDAuthenticationPackage")

typedef enum _EID_INTERACTIVE_LOGON_SUBMIT_TYPE
{
	EID_INTERACTIVE_LOGON_SUBMIT_TYPE_VANILLIA,
} EID_INTERACTIVE_LOGON_SUBMIT_TYPE;

typedef struct _EID_INTERACTIVE_LOGON 
{
    EID_INTERACTIVE_LOGON_SUBMIT_TYPE MessageType; // KerbCertificateLogon
    UNICODE_STRING LogonDomainName; // OPTIONAL, if supplied, used to locate the account forest
    UNICODE_STRING UserName;   // OPTIONAL, if supplied, used to locate the account
    UNICODE_STRING Pin;
    ULONG Flags;               // additional flags
    ULONG CspDataLength;
    PUCHAR CspData;            // contains the smartcard CSP data
} EID_INTERACTIVE_LOGON, *PEID_INTERACTIVE_LOGON;

typedef struct _EID_INTERACTIVE_UNLOCK_LOGON
{
    EID_INTERACTIVE_LOGON Logon;
    LUID LogonId;
} EID_INTERACTIVE_UNLOCK_LOGON, *PEID_INTERACTIVE_UNLOCK_LOGON;

typedef enum _EID_PROFILE_BUFFER_TYPE
{
	EIDInteractiveProfile = 2,
} EID_PROFILE_BUFFER_TYPE;

// based on _KERB_SMARTCARD_CSP_INFO 
typedef struct _EID_SMARTCARD_CSP_INFO 
{
  DWORD dwCspInfoLen;
  DWORD MessageType;
  union {
    PVOID ContextInformation;
    ULONG64 SpaceHolderForWow64;
  } ;
  DWORD flags;
  DWORD KeySpec;
  ULONG nCardNameOffset;
  ULONG nReaderNameOffset;
  ULONG nContainerNameOffset;
  ULONG nCSPNameOffset;
  TCHAR bBuffer[sizeof(DWORD)];
} EID_SMARTCARD_CSP_INFO, 
 *PEID_SMARTCARD_CSP_INFO;

typedef struct _EID_INTERACTIVE_PROFILE
{
  EID_PROFILE_BUFFER_TYPE MessageType;
  USHORT LogonCount;
  USHORT BadPasswordCount;
  LARGE_INTEGER LogonTime;
  LARGE_INTEGER LogoffTime;
  LARGE_INTEGER KickOffTime;
  LARGE_INTEGER PasswordLastSet;
  LARGE_INTEGER PasswordCanChange;
  LARGE_INTEGER PasswordMustChange;
  UNICODE_STRING LogonScript;
  UNICODE_STRING HomeDirectory;
  UNICODE_STRING FullName;
  UNICODE_STRING ProfilePath;
  UNICODE_STRING HomeDirectoryDrive;
  UNICODE_STRING LogonServer;
  ULONG UserFlags;
} EID_INTERACTIVE_PROFILE, 
 *PEID_INTERACTIVE_PROFILE;

typedef enum _EID_CREDENTIAL_PROVIDER_READER_STATE
{
	EIDCPRSConnecting,
	EIDCPRSConnected,
	EIDCPRSDisconnected,
	EIDCPRSThreadFinished,
} EID_CREDENTIAL_PROVIDER_READER_STATE;

typedef enum _EID_CALLPACKAGE_MESSAGE
{
	EIDCMCreateStoredCredential,
	EIDCMUpdateStoredCredential,
	EIDCMRemoveStoredCredential,
	EIDCMHasStoredCredential,
} EID_CALLPACKAGE_MESSAGE;

typedef struct _EID_CALLPACKAGE_BUFFER
{
	EID_CALLPACKAGE_MESSAGE MessageType;
	DWORD dwRid;
	PWSTR szPassword;		// used if EIDCMCreateStoredCredential
	USHORT usPasswordLen;	// can be 0 if null terminated
	PWSTR szProvider;		// used if EIDCMCreateStoredCredential
	PWSTR szContainer;		// used if EIDCMCreateStoredCredential
	DWORD dwKeySpec;		// used if EIDCMCreateStoredCredential

} EID_CALLPACKAGE_BUFFER, *PEID_CALLPACKAGE_BUFFER;