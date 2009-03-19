
#include "CEIDFilter.h"
#include "../EIDCardLibrary/GPO.h"

HRESULT CEIDFilter::UpdateRemoteCredential(      
    const CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION *pcpcsIn,
    CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION *pcpcsOut
)
{
	UNREFERENCED_PARAMETER(pcpcsIn);
	UNREFERENCED_PARAMETER(pcpcsOut);
	return S_OK;
}

HRESULT CEIDFilter::Filter(      
    CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus,
    DWORD dwFlags,
    GUID *rgclsidProviders,
    BOOL *rgbAllow,
    DWORD cProviders
)
{
	UNREFERENCED_PARAMETER(dwFlags);
	BOOL fFilter = FALSE;
	if (cpus == CPUS_LOGON || cpus == CPUS_UNLOCK_WORKSTATION)
	{
		fFilter = (GetPolicyValue(scforceoption) == 1);
	}
	if (fFilter)
	{
		for (DWORD dwI = 0; dwI < cProviders; dwI++)
		{
			if (rgclsidProviders[dwI] == CLSID_PasswordCredentialProvider)
			{
				rgbAllow[dwI] = FALSE;
			}
		}
	}
	return S_OK;
}