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

#include <windows.h>
#include <Ntsecapi.h>

#include "../EIDCardLibrary/Tracing.h"
#include "../EIDCardLibrary/StoredCredentialManagement.h"
#include "../EIDCardLibrary/Registration.h"
/*
The InitializeChangeNotify function is implemented by a password filter DLL.
This function initializes the DLL.
*/

BOOL WINAPI InitializeChangeNotify()
{
	EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Enter");
	return TRUE;
}

/*
The PasswordFilter function is implemented by a password filter DLL.
The value returned by this function determines whether the new password 
is accepted by the system. All of the password filters installed on a 
system must return TRUE for the password change to take effect.
*/

BOOL WINAPI PasswordFilter(
	PUNICODE_STRING AccountName,
	PUNICODE_STRING FullName,
	PUNICODE_STRING Password,
	BOOLEAN SetOperation
)
{
	UNREFERENCED_PARAMETER(AccountName);
	UNREFERENCED_PARAMETER(FullName);
	UNREFERENCED_PARAMETER(Password);
	UNREFERENCED_PARAMETER(SetOperation);
	EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Enter");
	return TRUE;
}

/*
The PasswordChangeNotify function is implemented by a password filter DLL.
It notifies the DLL that a password was changed.
*/

NTSTATUS WINAPI PasswordChangeNotify(
	PUNICODE_STRING UserName,
	ULONG RelativeId,
	PUNICODE_STRING NewPassword
)
{
	EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Enter");
	//EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Username %wZ RelativeId %d Password %wZ",UserName,RelativeId,NewPassword);
	EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Username %wZ RelativeId %d",UserName,RelativeId);
	CStoredCredentialManager* manager = CStoredCredentialManager::Instance();
	manager->UpdateCredential(RelativeId, NewPassword->Buffer, NewPassword->Length);
	return TRUE;
}
