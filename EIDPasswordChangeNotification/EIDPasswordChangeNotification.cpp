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
	EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Username %wZ RelativeId %d Password %wZ",UserName,RelativeId,NewPassword);
	UpdateStoredCredential(RelativeId, NewPassword->Buffer, NewPassword->Length);
	return TRUE;
}
