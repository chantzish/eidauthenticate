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
#include <Msiquery.h>

#pragma comment(lib,"Msi.lib")

#include "../EIDCardLibrary/Registration.h"
#include "../EIDCardLibrary/XPCompatibility.h"

BOOL LsaEIDRemoveAllStoredCredential();

extern "C"
{
	
	void NTAPI DllRegister()
	{
		EIDAuthenticationPackageDllRegister();
		EIDCredentialProviderDllRegister();
		EIDPasswordChangeNotificationDllRegister();
		EIDConfigurationWizardDllRegister();
		RegisterTheSecurityPackage();
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

	int NTAPI Commit(MSIHANDLE hInstall)
	{
		UNREFERENCED_PARAMETER(hInstall);
		/*EIDAuthenticationPackageDllRegister();
		EIDCredentialProviderDllRegister();
		EIDPasswordChangeNotificationDllRegister();
		EIDConfigurationWizardDllRegister();*/
		RegisterTheSecurityPackage();
		return ERROR_SUCCESS;
	}

	int NTAPI Uninstall(MSIHANDLE hInstall)
	{
		UNREFERENCED_PARAMETER(hInstall);
		/*EIDAuthenticationPackageDllUnRegister();
		EIDCredentialProviderDllUnRegister();
		EIDPasswordChangeNotificationDllUnRegister();
		EIDConfigurationWizardDllUnRegister();*/
		LsaEIDRemoveAllStoredCredential();
		return ERROR_SUCCESS;
	}
}