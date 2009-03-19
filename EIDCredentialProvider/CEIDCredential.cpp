//
// THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
// ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO
// THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
// PARTICULAR PURPOSE.
//
// Copyright (c) 2006 Microsoft Corporation. All rights reserved.
//
//



#include "CEIDCredential.h"


#include "../EIDCardLibrary/guid.h"
#include "../EIDCardLibrary/EIDCardLibrary.h"
#include "../EIDCardLibrary/Package.h"
#include "../EIDCardLibrary/CContainer.h"


// CEIDCredential ////////////////////////////////////////////////////////

CEIDCredential::CEIDCredential(CContainer* container):
    _cRef(1),
    _pCredProvCredentialEvents(NULL)
{
	EIDCardLibraryTrace(WINEVENT_LEVEL_INFO,L"Creation");
	DllAddRef();
    ZeroMemory(_rgCredProvFieldDescriptors, sizeof(_rgCredProvFieldDescriptors));
    ZeroMemory(_rgFieldStatePairs, sizeof(_rgFieldStatePairs));
    ZeroMemory(_rgFieldStrings, sizeof(_rgFieldStrings));
	_pContainer = container;
	Initialize();
}

CEIDCredential::~CEIDCredential()
{
	if (_pContainer)
	{
		delete _pContainer;
	}
	if (_rgFieldStrings[SFI_PIN])
    {
        // CoTaskMemFree (below) deals with NULL, but StringCchLength does not.
        size_t lenPin;
        HRESULT hr = StringCchLengthW(_rgFieldStrings[SFI_PIN], 128, &(lenPin));
        if (SUCCEEDED(hr))
        {
            SecureZeroMemory(_rgFieldStrings[SFI_PIN], lenPin * sizeof(*_rgFieldStrings[SFI_PIN]));
        }
        else
        {
            // TODO: Determine how to handle count error here.
        }
    }
    for (int i = 0; i < ARRAYSIZE(_rgFieldStrings); i++)
    {
        CoTaskMemFree(_rgFieldStrings[i]);
        CoTaskMemFree(_rgCredProvFieldDescriptors[i].pszLabel);
    }

    DllRelease();
	EIDCardLibraryTrace(WINEVENT_LEVEL_INFO,L"Deletion");
}

// Initializes one credential with the field information passed in.
// Set the value of the SFI_USERNAME field to pwzUsername.
HRESULT CEIDCredential::Initialize(
    //CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus,
    //const CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR* rgcpfd,
    //const FIELD_STATE_PAIR* rgfsp
    )
{
    HRESULT hr = S_OK;
//    _cpus = cpus;

    // Copy the field descriptors for each field. This is useful if you want to vary the field
    // descriptors based on what Usage scenario the credential was created for.
    for (DWORD i = 0; SUCCEEDED(hr) && i < ARRAYSIZE(s_rgCredProvFieldDescriptors); i++)
    {
        _rgFieldStatePairs[i] = s_rgFieldStatePairs[i];
		hr = FieldDescriptorCopy(s_rgCredProvFieldDescriptors[i], &_rgCredProvFieldDescriptors[i]);
    }

	// Initialize the String value of all the fields.
    if (SUCCEEDED(hr))
	{
		SHStrDupW(_pContainer->GetUserNameW(), &_rgFieldStrings[SFI_USERNAME]);
	}
	if (SUCCEEDED(hr))
    {
        hr = SHStrDupW(L"", &_rgFieldStrings[SFI_PIN]);
    }
    if (SUCCEEDED(hr))
    {
        hr = SHStrDupW(L"Submit", &_rgFieldStrings[SFI_SUBMIT_BUTTON]);
    }
   if (SUCCEEDED(hr))
    {
        hr = SHStrDupW(L"Certificate detail", &_rgFieldStrings[SFI_CERTIFICATE]);
    }
    return S_OK;
}

CContainer* CEIDCredential::GetContainer()
{
	return _pContainer;
}
// LogonUI calls this in order to give us a callback in case we need to notify it of anything.
HRESULT CEIDCredential::Advise(
    ICredentialProviderCredentialEvents* pcpce
    )
{
	if (_pCredProvCredentialEvents != NULL)
    {
        _pCredProvCredentialEvents->Release();
    }
    _pCredProvCredentialEvents = pcpce;
    _pCredProvCredentialEvents->AddRef();

    return S_OK;
}

void CEIDCredential::SetUsageScenario(CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus, DWORD dwFlags)
{
	_cpus = cpus;
	_dwFlags = dwFlags;
}

// LogonUI calls this to tell us to release the callback.
HRESULT CEIDCredential::UnAdvise()
{
	if (_pCredProvCredentialEvents)
    {
        _pCredProvCredentialEvents->Release();
    }
    _pCredProvCredentialEvents = NULL;
    return S_OK;
}

// LogonUI calls this function when our tile is selected (zoomed)
// If you simply want fields to show/hide based on the selected state,
// there's no need to do anything here - you can set that up in the 
// field definitions.  But if you want to do something
// more complicated, like change the contents of a field when the tile is
// selected, you would do it here.
HRESULT CEIDCredential::SetSelected(BOOL* pbAutoLogon)  
{
	*pbAutoLogon = FALSE;  
    return S_OK;
}

// Similarly to SetSelected, LogonUI calls this when your tile was selected
// and now no longer is.  The most common thing to do here (which we do below)
// is to clear out the Pin field.
HRESULT CEIDCredential::SetDeselected()
{
    HRESULT hr = S_OK;
	if (_rgFieldStrings[SFI_PIN])
    {
        // CoTaskMemFree (below) deals with NULL, but StringCchLength does not.
        size_t lenPin;
        hr = StringCchLengthW(_rgFieldStrings[SFI_PIN], 128, &(lenPin));
        if (SUCCEEDED(hr))
        {
            SecureZeroMemory(_rgFieldStrings[SFI_PIN], lenPin * sizeof(*_rgFieldStrings[SFI_PIN]));
        
            CoTaskMemFree(_rgFieldStrings[SFI_PIN]);
            hr = SHStrDupW(L"", &_rgFieldStrings[SFI_PIN]);
        }

        if (SUCCEEDED(hr) && _pCredProvCredentialEvents)
        {
            _pCredProvCredentialEvents->SetFieldString(this, SFI_PIN, _rgFieldStrings[SFI_PIN]);
        }
    }

    return hr;
}

// Get info for a particular field of a tile. Called by logonUI to get information to 
// display the tile.
HRESULT CEIDCredential::GetFieldState(
    DWORD dwFieldID,
    CREDENTIAL_PROVIDER_FIELD_STATE* pcpfs,
    CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE* pcpfis
    )
{
    HRESULT hr;
    if (dwFieldID < ARRAYSIZE(_rgFieldStatePairs) && pcpfs && pcpfis)
    {
        *pcpfis = _rgFieldStatePairs[dwFieldID].cpfis;
        *pcpfs = _rgFieldStatePairs[dwFieldID].cpfs;

        hr = S_OK;
    }
    else
    {
        hr = E_INVALIDARG;
    }
    return hr;
}

// Sets ppwsz to the string value of the field at the index dwFieldID.
HRESULT CEIDCredential::GetStringValue(
    DWORD dwFieldID, 
    PWSTR* ppwsz
    )
{
    HRESULT hr;
    // Check to make sure dwFieldID is a legitimate index.
    if (dwFieldID < ARRAYSIZE(_rgCredProvFieldDescriptors) && ppwsz) 
    {
        // Make a copy of the string and return that. The caller
        // is responsible for freeing it.
        hr = SHStrDupW(_rgFieldStrings[dwFieldID], ppwsz);
    }
    else
    {
        hr = E_INVALIDARG;
    }

    return hr;
}

// Get the image to show in the user tile.
HRESULT CEIDCredential::GetBitmapValue(
    DWORD dwFieldID, 
    HBITMAP* phbmp
    )
{
    HRESULT hr;
	if ((SFI_TILEIMAGE == dwFieldID) && phbmp)
    {
        HBITMAP hbmp;
		/*LPWSTR swImagePath = NULL;
		ULONG swImagePathLen = 0;
		HRESULT Status;
		//try to load the user tile (name is in _rgFieldStrings[SFI_USERNAME])
		Status = CallAuthPackage(_rgFieldStrings[SFI_USERNAME],&swImagePath,&swImagePathLen);
		if (SUCCEEDED(Status))
		{
			hbmp = (HBITMAP) LoadImage(NULL, swImagePath,IMAGE_BITMAP,0,0,LR_LOADFROMFILE);
			if (hbmp != NULL)
			{
				hr = S_OK;
				*phbmp = hbmp;
			}
			else
			{
				hr = HRESULT_FROM_WIN32(GetLastError());
			}
			__try
			{
				//NTSTATUS status = LsaFreeMemory(swImagePath);
				//EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"6 %d %d",status, STATUS_SUCCESS);
			}
			#pragma warning(push)
#pragma warning(disable : 6320)
			__except(EXCEPTION_EXECUTE_HANDLER)
		#pragma warning(pop)
			{
				EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"NT exception 0x%08x",GetExceptionCode());
				return GetExceptionCode();
			}
		}
		else*/
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"7");
			// else load the bitmap saved in the resource.
			hbmp = LoadBitmap(HINST_THISDLL, MAKEINTRESOURCE(IDB_TILE_IMAGE));
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"8");
			if (hbmp != NULL)
			{
				hr = S_OK;
				*phbmp = hbmp;
			}
			else
			{
				hr = HRESULT_FROM_WIN32(GetLastError());
			}
		}
    }
    else
    {
        hr = E_INVALIDARG;
    }
    return hr;
}

// Sets pdwAdjacentTo to the index of the field the submit button should be 
// adjacent to. We recommend that the submit button is placed next to the last
// field which the user is required to enter information in. Optional fields
// should be below the submit button.
HRESULT CEIDCredential::GetSubmitButtonValue(
    DWORD dwFieldID,
    DWORD* pdwAdjacentTo
    )
{
    HRESULT hr;
    if (SFI_SUBMIT_BUTTON == dwFieldID && pdwAdjacentTo)
    {
        // pdwAdjacentTo is a pointer to the fieldID you want the submit button to 
        // appear next to.
        *pdwAdjacentTo = SFI_PIN;
        hr = S_OK;
    }
    else
    {
        hr = E_INVALIDARG;
    }
    return hr;
}

// Sets the value of a field which can accept a string as a value.
// This is called on each keystroke when a user types into an edit field
HRESULT CEIDCredential::SetStringValue(
    DWORD dwFieldID, 
    PCWSTR pwz      
    )
{
    HRESULT hr;

    if (dwFieldID < ARRAYSIZE(_rgCredProvFieldDescriptors) && 
       (CPFT_EDIT_TEXT == _rgCredProvFieldDescriptors[dwFieldID].cpft || 
        CPFT_PASSWORD_TEXT == _rgCredProvFieldDescriptors[dwFieldID].cpft)) 
    {
        PWSTR* ppwszStored = &_rgFieldStrings[dwFieldID];
        CoTaskMemFree(*ppwszStored);

        hr = SHStrDupW(pwz, ppwszStored);
    }
    else
    {
        hr = E_INVALIDARG;
    }
    return hr;
}

//------------- 
// The following methods are for logonUI to get the values of various UI elements and then communicate
// to the credential about what the user did in that field.  However, these methods are not implemented
// because our tile doesn't contain these types of UI elements
HRESULT CEIDCredential::GetCheckboxValue(
    DWORD dwFieldID, 
    BOOL* pbChecked,
    PWSTR* ppwszLabel
    )
{
    UNREFERENCED_PARAMETER(dwFieldID);
    UNREFERENCED_PARAMETER(pbChecked);
    UNREFERENCED_PARAMETER(ppwszLabel);

    return E_NOTIMPL;
}

HRESULT CEIDCredential::GetComboBoxValueCount(
    DWORD dwFieldID, 
    DWORD* pcItems, 
    DWORD* pdwSelectedItem
    )
{
    UNREFERENCED_PARAMETER(dwFieldID);
    UNREFERENCED_PARAMETER(pcItems);
    UNREFERENCED_PARAMETER(pdwSelectedItem);
	return E_NOTIMPL;
}

HRESULT CEIDCredential::GetComboBoxValueAt(
    DWORD dwFieldID, 
    DWORD dwItem,
    PWSTR* ppwszItem
    )
{
    UNREFERENCED_PARAMETER(dwFieldID);
    UNREFERENCED_PARAMETER(dwItem);
    UNREFERENCED_PARAMETER(ppwszItem);
	return E_NOTIMPL;
}

HRESULT CEIDCredential::SetCheckboxValue(
    DWORD dwFieldID, 
    BOOL bChecked
    )
{
    UNREFERENCED_PARAMETER(dwFieldID);
    UNREFERENCED_PARAMETER(bChecked);

    return E_NOTIMPL;
}

HRESULT CEIDCredential::SetComboBoxSelectedValue(
    DWORD dwFieldID,
    DWORD dwSelectedItem
    )
{
    UNREFERENCED_PARAMETER(dwFieldID);
    UNREFERENCED_PARAMETER(dwSelectedItem);
	return E_NOTIMPL;
}

HRESULT CEIDCredential::CommandLinkClicked(DWORD dwFieldID)
{
	HRESULT hr;
	if (dwFieldID < ARRAYSIZE(_rgCredProvFieldDescriptors) && 
       (CPFT_COMMAND_LINK == _rgCredProvFieldDescriptors[dwFieldID].cpft)) 
    {
		if (_pCredProvCredentialEvents)
		{
			HWND hWnd;
			_pCredProvCredentialEvents->OnCreatingWindow(&hWnd);
			_pContainer->ViewCertificate(hWnd);  
		}
		hr = S_OK;
	}
    else
    {
        hr = E_INVALIDARG;
    }
    return S_OK;
}
//------ end of methods for controls we don't have in our tile ----//

// Collect the username and password into a serialized credential for the correct usage scenario 
// (logon/unlock is what's demonstrated in this sample).  LogonUI then passes these credentials 
// back to the system to log on.
// http://msdn.microsoft.com/en-us/library/bb776026(VS.85).aspx
HRESULT CEIDCredential::GetSerialization(
    CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE* pcpgsr,
    CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* pcpcs, 
    PWSTR* ppwszOptionalStatusText, 
    CREDENTIAL_PROVIDER_STATUS_ICON* pcpsiOptionalStatusIcon
    )
{
    UNREFERENCED_PARAMETER(ppwszOptionalStatusText);
    UNREFERENCED_PARAMETER(pcpsiOptionalStatusIcon);
    HRESULT hr;
	
    WCHAR wsz[MAX_COMPUTERNAME_LENGTH+1];
    DWORD cch = ARRAYSIZE(wsz);
    if (GetComputerNameW(wsz, &cch))
    {
        PWSTR pwzProtectedPin;

        hr = ProtectIfNecessaryAndCopyPassword(_rgFieldStrings[SFI_PIN], _cpus, _dwFlags,  &pwzProtectedPin);

        if (SUCCEEDED(hr))
        {
            EID_INTERACTIVE_UNLOCK_LOGON kiul;
			//KERB_INTERACTIVE_UNLOCK_LOGON kiul;

            // Initialize kiul with weak references to our credential.
            hr = EIDUnlockLogonInit(wsz, _rgFieldStrings[SFI_USERNAME], pwzProtectedPin, _cpus,  &kiul);

            if (SUCCEEDED(hr))
            {
                // We use EID_INTERACTIVE_UNLOCK_LOGON in both unlock and logon scenarios.  It contains a
                // EID_INTERACTIVE_LOGON to hold the creds plus a LUID that is filled in for us by Winlogon
                // as necessary.
				PEID_SMARTCARD_CSP_INFO pCspInfo = _pContainer->GetCSPInfo();
				if (pCspInfo)
				{
					hr = EIDUnlockLogonPack(kiul, pCspInfo, &pcpcs->rgbSerialization, &pcpcs->cbSerialization);
					_pContainer->FreeCSPInfo(pCspInfo);

					if (SUCCEEDED(hr))
					{
						ULONG ulAuthPackage;

						hr = RetrieveNegotiateAuthPackage(&ulAuthPackage);
						if (SUCCEEDED(hr))
						{
							pcpcs->ulAuthenticationPackage = ulAuthPackage;
							pcpcs->clsidCredentialProvider = CLSID_CEIDProvider;

							// At this point the credential has created the serialized credential used for logon
							// By setting this to CPGSR_RETURN_CREDENTIAL_FINISHED we are letting logonUI know
							// that we have all the information we need and it should attempt to submit the 
							// serialized credential.
							*pcpgsr = CPGSR_RETURN_CREDENTIAL_FINISHED;
						}
					}
				}
            }

            CoTaskMemFree(pwzProtectedPin);
        }
    }
    else
    {
        DWORD dwErr = GetLastError();
        hr = HRESULT_FROM_WIN32(dwErr);
    }

    return hr;
}

struct REPORT_RESULT_STATUS_INFO
{
    NTSTATUS ntsStatus;
    NTSTATUS ntsSubstatus;
    PWSTR     pwzMessage;
    CREDENTIAL_PROVIDER_STATUS_ICON cpsi;
};

static const REPORT_RESULT_STATUS_INFO s_rgLogonStatusInfo[] =
{
    { STATUS_LOGON_FAILURE, STATUS_SUCCESS, L"Incorrect Pin or username.", CPSI_ERROR, },
    { STATUS_ACCOUNT_RESTRICTION, STATUS_ACCOUNT_DISABLED, L"The account is disabled.", CPSI_WARNING },
};

// ReportResult is completely optional.  Its purpose is to allow a credential to customize the string
// and the icon displayed in the case of a logon failure.  For example, we have chosen to 
// customize the error shown in the case of bad username/Pin and in the case of the account
// being disabled.

HRESULT CEIDCredential::ReportResult(
    NTSTATUS ntsStatus, 
    NTSTATUS ntsSubstatus,
    PWSTR* ppwszOptionalStatusText, 
    CREDENTIAL_PROVIDER_STATUS_ICON* pcpsiOptionalStatusIcon
    )
{
    if (ppwszOptionalStatusText) *ppwszOptionalStatusText = L"Unknow Error";
    if (pcpsiOptionalStatusIcon) *pcpsiOptionalStatusIcon = CPSI_NONE;
	
	if (ntsStatus == STATUS_SUCCESS)
	{
		_pContainer->TriggerRemovePolicy();
	}

    DWORD dwStatusInfo = (DWORD)-1;

    // Look for a match on status and substatus.
    for (DWORD i = 0; i < ARRAYSIZE(s_rgLogonStatusInfo); i++)
    {
        if (s_rgLogonStatusInfo[i].ntsStatus == ntsStatus && s_rgLogonStatusInfo[i].ntsSubstatus == ntsSubstatus)
        {
            dwStatusInfo = i;
            break;
        }
    }

    if ((DWORD)-1 != dwStatusInfo)
    {
			if (pcpsiOptionalStatusIcon)
				*pcpsiOptionalStatusIcon = s_rgLogonStatusInfo[dwStatusInfo].cpsi;
    }

	if (ppwszOptionalStatusText)
	{
	    // get message from system table
		PWSTR Error = NULL;
		DWORD dwLen = 2048;
		Error = (PWSTR) CoTaskMemAlloc(dwLen);
		FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM,NULL,LsaNtStatusToWinError(ntsStatus),0,(PWSTR)Error,dwLen,NULL);
		*ppwszOptionalStatusText = Error;

	}
    // If we failed the logon, try to erase the Pin field.
    if (!SUCCEEDED(HRESULT_FROM_NT(ntsStatus)))
    {
        if (_pCredProvCredentialEvents)
        {
            _pCredProvCredentialEvents->SetFieldString(this, SFI_PIN, L"");
        }
    }

    // Since NULL is a valid value for *ppwszOptionalStatusText and *pcpsiOptionalStatusIcon
    // this function can't fail.
    
	return S_OK;
}

