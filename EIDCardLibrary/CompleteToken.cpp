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
#define WIN32_NO_STATUS
#include <windows.h>

#define SECURITY_WIN32
#include <sspi.h>

#include <Ntsecapi.h>
#include <NtSecPkg.h>
#include <SubAuth.h>
#include <lm.h>
#include <Sddl.h>

#include "Tracing.h"

BOOL NameToSid(WCHAR* UserName, PLSA_DISPATCH_TABLE FunctionTable, PSID* pUserSid);
BOOL GetGroups(WCHAR* UserName,PGROUP_USERS_INFO_1 *lpGroupInfo, LPDWORD pTotalEntries);
BOOL GetLocalGroups(WCHAR* UserName,PGROUP_USERS_INFO_0 *lpGroupInfo, LPDWORD pTotalEntries);
BOOL GetPrimaryGroupSidFromUserSid(PSID UserSID,PLSA_DISPATCH_TABLE FunctionTable, PSID *PrimaryGroupSID);
void DebugPrintSid(WCHAR* Name, PSID Sid);

NTSTATUS CheckAuthorization(PWSTR UserName, NTSTATUS *SubStatus, LARGE_INTEGER *ExpirationTime);

NTSTATUS UserNameToToken(__in PLSA_UNICODE_STRING AccountName,
						__in PLSA_DISPATCH_TABLE FunctionTable,
						__out PLSA_TOKEN_INFORMATION_V2 *Token,
						__out LPDWORD TokenLength,
						__out PNTSTATUS SubStatus
						) {
	EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Enter");
	PLSA_TOKEN_INFORMATION_V2 TokenInformation;
	PTOKEN_GROUPS pTokenGroups=NULL;
	PGROUP_USERS_INFO_1 pGroupInfo;
	PGROUP_USERS_INFO_0 pLocalGroupInfo;

	DWORD NumberOfGroups;
	DWORD NumberOfLocalGroups;
	BOOL bResult;
	PSID UserSid = NULL, PrimaryGroupSid = NULL, *pGroupSid;
	DWORD Size;
	PBYTE Offset;
	DWORD i;
	NTSTATUS Status;
	LARGE_INTEGER ExpirationTime;
	// convert AccountName to WSTR
	EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Convert");
	WCHAR UserName[UNLEN+1];

	wcsncpy_s(UserName,UNCLEN,AccountName->Buffer,AccountName->Length/2);
	UserName[AccountName->Length/2]=0;
	
	// check authorization
	Status = CheckAuthorization(UserName, SubStatus, &ExpirationTime);
	if (Status != STATUS_SUCCESS)
	{
		return Status;
	}
	// get the number of groups
	bResult = GetGroups(UserName,&pGroupInfo,&NumberOfGroups);
	if (!bResult)
	{
		EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"GetGroups error");
		return STATUS_DATA_ERROR;
	}
	bResult = GetLocalGroups(UserName,&pLocalGroupInfo,&NumberOfLocalGroups);
	if (!bResult)
	{
		EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"GetGroups error");
		NetApiBufferFree(pGroupInfo);
		return STATUS_DATA_ERROR;
	}

	// get SID
	// User
	EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"User");
	bResult = NameToSid(UserName,FunctionTable,&UserSid);
	if (!bResult)
	{
		EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"NameToSid");
		NetApiBufferFree(pGroupInfo);
		NetApiBufferFree(pLocalGroupInfo);
		return STATUS_DATA_ERROR;
	}
	// Primary Group Id
	EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Primary Group Id");
	bResult = GetPrimaryGroupSidFromUserSid(UserSid,FunctionTable,&PrimaryGroupSid);
	if (!bResult)
	{
		EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"GetGroups");
		NetApiBufferFree(pGroupInfo);
		NetApiBufferFree(pLocalGroupInfo);
		return STATUS_DATA_ERROR;
	}
	Size = 0;
	// Group
	pGroupSid = new PSID[NumberOfGroups+NumberOfLocalGroups];
	EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Group");
	for (i=0; i<NumberOfGroups; i++)
	{
		NameToSid(pGroupInfo[i].grui1_name,FunctionTable,&pGroupSid[i]);
		Size += GetLengthSid(pGroupSid[i]);
	}
	for (i=0; i<NumberOfLocalGroups; i++)
	{
		NameToSid(pLocalGroupInfo[i].grui0_name,FunctionTable,&pGroupSid[NumberOfGroups+i]);
		Size += GetLengthSid(pGroupSid[NumberOfGroups+i]);
	}	// allocation
	// compute the size
	Size += sizeof(LSA_TOKEN_INFORMATION_V2); // struct
	Size += GetLengthSid(UserSid) + GetLengthSid(PrimaryGroupSid);//sid user and primary group
	Size += sizeof(DWORD) + (sizeof(SID_AND_ATTRIBUTES)) * (NumberOfGroups+NumberOfLocalGroups); // groups

	TokenInformation = (PLSA_TOKEN_INFORMATION_V2) FunctionTable->AllocateLsaHeap(Size);
	if (TokenInformation == NULL)
	{
		EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"TokenInformation NULL");
		NetApiBufferFree(pGroupInfo);
		NetApiBufferFree(pLocalGroupInfo);
		return STATUS_NO_MEMORY;
	}
	// update offset and copy info
	Offset =  (PBYTE)TokenInformation + sizeof(LSA_TOKEN_INFORMATION_V1);
	TokenInformation->User.User.Sid = (PSID)Offset;
	CopySid(GetLengthSid(UserSid),Offset,UserSid);
	DebugPrintSid(UserName,UserSid);
	TokenInformation->User.User.Attributes = 0; // cf msdn, no attributes definied for users sid
	Offset += GetLengthSid(UserSid);
	FunctionTable->FreeLsaHeap(UserSid);

	TokenInformation->PrimaryGroup.PrimaryGroup = (PSID)Offset;
	CopySid(GetLengthSid(PrimaryGroupSid),Offset,PrimaryGroupSid);
	DebugPrintSid(L"PrimaryGroupId", PrimaryGroupSid);
	Offset += GetLengthSid(PrimaryGroupSid);
	FunctionTable->FreeLsaHeap(PrimaryGroupSid);

	TokenInformation->Groups = (PTOKEN_GROUPS) Offset;
	pTokenGroups = (PTOKEN_GROUPS)Offset;
	pTokenGroups->GroupCount = NumberOfGroups + NumberOfLocalGroups;
	// -ANYSIZE_ARRAY because TOKEN_GROUPS contain "ANYSIZE_ARRAY" (=1) SID_AND_ATTRIBUTES
	Offset += sizeof(TOKEN_GROUPS) + sizeof(SID_AND_ATTRIBUTES) * (NumberOfGroups + NumberOfLocalGroups -ANYSIZE_ARRAY); 
	// cause TOKEN_GROUPS contains one SID_AND_ATTRIBUTES
	EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Group Struct time");

	for (i=0; i<NumberOfGroups; i++)
	{
		// attributes get directly from the struct
		pTokenGroups->Groups[i].Attributes = pGroupInfo[i].grui1_attributes;
		pTokenGroups->Groups[i].Sid = (PSID)Offset;
		CopySid(GetLengthSid(pGroupSid[i]),Offset ,pGroupSid[i]);
		Offset += GetLengthSid(pGroupSid[i]);
		DebugPrintSid(pGroupInfo[i].grui1_name, pGroupSid[i]);
		FunctionTable->FreeLsaHeap(pGroupSid[i]);
	}
	for (i=0; i<NumberOfLocalGroups; i++)
	{
		// get the attributes of group since the struct doesn't containt attributes
		if (*GetSidSubAuthority(pGroupSid[NumberOfGroups+i],0)!=SECURITY_BUILTIN_DOMAIN_RID)
		{
			pTokenGroups->Groups[NumberOfGroups+i].Attributes=SE_GROUP_ENABLED|SE_GROUP_ENABLED_BY_DEFAULT;
		}
		else
		{
			pTokenGroups->Groups[NumberOfGroups+i].Attributes=0;
		}
		pTokenGroups->Groups[NumberOfGroups+i].Sid = (PSID)Offset;
		CopySid(GetLengthSid(pGroupSid[NumberOfGroups+i]),Offset,pGroupSid[NumberOfGroups+i]);
		Offset += GetLengthSid(pGroupSid[NumberOfGroups+i]);
		DebugPrintSid(pLocalGroupInfo[i].grui0_name, pGroupSid[NumberOfGroups+i]);
		FunctionTable->FreeLsaHeap(pGroupSid[NumberOfGroups+i]);
	}
	delete[] pGroupSid;

	// Expiration time
	EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Expiration time");
	TokenInformation->ExpirationTime = ExpirationTime;
	
	// privileges
	EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"privileges");
	TokenInformation->Privileges = NULL;

	// owner
	EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"owner");
	TokenInformation->Owner.Owner = NULL;

	// dacl
	EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"dacl");
	TokenInformation->DefaultDacl.DefaultDacl = NULL;

	EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"TokenInformation done");

	*TokenLength = Size;
	*Token = TokenInformation;

	NetApiBufferFree(pGroupInfo);
	NetApiBufferFree(pLocalGroupInfo);
	EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Leave");
	return STATUS_SUCCESS;
}


BOOL NameToSid(WCHAR* UserName, PLSA_DISPATCH_TABLE FunctionTable, PSID *pUserSid)
{
	BOOL bResult;
	SID_NAME_USE Use;
	WCHAR checkDomainName[UNCLEN+1];
	DWORD cchReferencedDomainName=0;

	DWORD dLengthSid = 0;
	bResult = LookupAccountNameW( NULL, UserName, NULL,&dLengthSid,NULL, &cchReferencedDomainName, &Use);
	
	*pUserSid = FunctionTable->AllocateLsaHeap(dLengthSid);
	cchReferencedDomainName=UNCLEN;
	bResult = LookupAccountNameW( NULL, UserName, *pUserSid,&dLengthSid,checkDomainName, &cchReferencedDomainName, &Use);
	if (!bResult) 
	{
		EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Unable to LookupAccountNameW 0x%08x",GetLastError());
		return FALSE;
	}
	return TRUE;
}

BOOL GetGroups(WCHAR* UserName,PGROUP_USERS_INFO_1 *lpGroupInfo, LPDWORD pTotalEntries)
{
	NET_API_STATUS Status;
	DWORD NumberOfEntries;
	Status = NetUserGetGroups(NULL,UserName,1,(LPBYTE*)lpGroupInfo,MAX_PREFERRED_LENGTH,&NumberOfEntries,pTotalEntries);
	if (Status != NERR_Success)
	{
		EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Unable to NetUserGetGroups 0x%08x",Status);
		return FALSE;
	}
	return TRUE;
}

BOOL GetLocalGroups(WCHAR* UserName,PGROUP_USERS_INFO_0 *lpGroupInfo, LPDWORD pTotalEntries)
{
	NET_API_STATUS Status;
	DWORD NumberOfEntries;
	Status = NetUserGetLocalGroups(NULL,UserName,0,0,(LPBYTE*)lpGroupInfo,MAX_PREFERRED_LENGTH,&NumberOfEntries,pTotalEntries);
	if (Status != NERR_Success)
	{
		EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Unable to NetUserGetLocalGroups 0x%08x",Status);
		return FALSE;
	}
	return TRUE;
}

BOOL GetPrimaryGroupSidFromUserSid(PSID UserSID,PLSA_DISPATCH_TABLE FunctionTable, PSID *PrimaryGroupSID)
{
	// duplicate the user sid and replace the last subauthority by DOMAIN_GROUP_RID_USERS
	// cf http://msdn.microsoft.com/en-us/library/aa379649.aspx
	UCHAR SubAuthorityCount;
	*PrimaryGroupSID = FunctionTable->AllocateLsaHeap(GetLengthSid(UserSID));
	CopySid(GetLengthSid(UserSID),*PrimaryGroupSID,UserSID);
	SubAuthorityCount = *GetSidSubAuthorityCount(*PrimaryGroupSID);
	// last SubAuthority = RID
	*GetSidSubAuthority(*PrimaryGroupSID, SubAuthorityCount-1) = DOMAIN_GROUP_RID_USERS;
	return TRUE;
}

void DebugPrintSid(WCHAR* Name, PSID Sid)
{
	LPTSTR chSID;
	ConvertSidToStringSid(Sid,&chSID);
	EIDCardLibraryTrace(WINEVENT_LEVEL_INFO,L"Name %s Sid %s",Name,chSID);
	LocalFree(chSID);
}

// check is the account is valid and not disabled
NTSTATUS CheckAuthorization(PWSTR UserName, NTSTATUS *SubStatus, LARGE_INTEGER *ExpirationTime)
{
	NTSTATUS Status;
	USER_INFO_4 *pUserInfo = NULL;
	if((Status=NetUserGetInfo(NULL, UserName, 4, (LPBYTE*)&pUserInfo))!=0)
	{
		switch(Status)
		{
		case ERROR_ACCESS_DENIED:
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"User not found (%s): ACCESS DENIED",UserName);
			Status = STATUS_ACCESS_DENIED;
			break;
		case NERR_InvalidComputer:
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"User not found (%s): Invalid computer",UserName);
			Status = STATUS_NO_SUCH_DOMAIN;
			break;
		case NERR_UserNotFound:
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"User not found (%s): No such user",UserName);
			Status = STATUS_NO_SUCH_USER;
			break;
		default:
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"User not found (%s): Unknown error 0x%08x",UserName,Status);
			Status = STATUS_NO_SUCH_USER;
			break;
		}
		if(pUserInfo) NetApiBufferFree(pUserInfo);
		return Status;
	}

	if(pUserInfo->usri4_flags&UF_ACCOUNTDISABLE)
	{
		EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Account disabled: ACCOUNT_DISABLED");
		*SubStatus = STATUS_ACCOUNT_DISABLED;
		if(pUserInfo) NetApiBufferFree(pUserInfo);
		return STATUS_ACCOUNT_RESTRICTION;
	}
	ExpirationTime->QuadPart = 9223372036854775807;
	if (pUserInfo->usri4_logon_hours)
	{
		DWORD dwPosLogon, dwPosLogoff, dwHours;
		SYSTEMTIME SystemTime;
		FILETIME FileTime;
		GetSystemTime(&SystemTime);
		dwPosLogon = SystemTime.wDayOfWeek*24 + SystemTime.wHour;
		if (!((pUserInfo->usri4_logon_hours[dwPosLogon/8] >> (dwPosLogon % 8)) & 1))
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"STATUS_INVALID_LOGON_HOURS");
			*SubStatus = STATUS_INVALID_LOGON_HOURS;
			return STATUS_ACCOUNT_RESTRICTION;
		}
		else
		{
			// logon authorized
			// iterates to find the first 0
			for (dwHours = 1 ; dwHours < 7 * 24 + 1; dwHours++)
			{
				dwPosLogoff = (dwPosLogon + dwHours) % (7 * 24);
				if (!((pUserInfo->usri4_logon_hours[dwPosLogoff/8] >> (dwPosLogoff % 8)) & 1))
				{
					// Logon authorized not everytime
					LARGE_INTEGER Hour;
					Hour.LowPart = 0x61C46800;
					Hour.HighPart = 8;
					SystemTime.wMinute = 0;
					SystemTime.wSecond = 0;
					SystemTime.wMilliseconds = 0;
					SystemTimeToFileTime(&SystemTime, &FileTime);
					ExpirationTime->LowPart = FileTime.dwLowDateTime;
					ExpirationTime->HighPart = FileTime.dwHighDateTime;
					ExpirationTime->QuadPart +=  Hour.QuadPart * dwHours; 
					break;
				}
			}
		}
	}
	if (wcscmp(pUserInfo->usri4_logon_server,L"\\\\*") != 0)
	{
		EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"STATUS_INVALID_WORKSTATION");
		*SubStatus = STATUS_INVALID_WORKSTATION;
		return STATUS_ACCOUNT_RESTRICTION;
	}

	NetApiBufferFree(pUserInfo);
	return STATUS_SUCCESS;
}






















