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

//
// THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
// ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO
// THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
// PARTICULAR PURPOSE.
//
// Copyright (c) 2006 Microsoft Corporation. All rights reserved.
//
// Helper functions for copying parameters and packaging the buffer
// for GetSerialization.


#include "helpers.h"
#include <intsafe.h>
#include <wincred.h>

// 
// Copies the field descriptor pointed to by rcpfd into a buffer allocated 
// using CoTaskMemAlloc. Returns that buffer in ppcpfd.
// 
HRESULT FieldDescriptorCoAllocCopy(
                                   const CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR& rcpfd,
                                   CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR** ppcpfd
                                   )
{
    HRESULT hr;
    DWORD cbStruct = sizeof(CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR);

    CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR* pcpfd = 
        (CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR*)CoTaskMemAlloc(cbStruct);

    if (pcpfd)
    {
        pcpfd->dwFieldID = rcpfd.dwFieldID;
        pcpfd->cpft = rcpfd.cpft;

        if (rcpfd.pszLabel)
        {
            hr = SHStrDupW(rcpfd.pszLabel, &pcpfd->pszLabel);
        }
        else
        {
            pcpfd->pszLabel = NULL;
            hr = S_OK;
        }
    }
    else
    {
        hr = E_OUTOFMEMORY;
    }
    if (SUCCEEDED(hr))
    {
        *ppcpfd = pcpfd;
    }
    else
    {
        CoTaskMemFree(pcpfd);  
        *ppcpfd = NULL;
    }


    return hr;
}

//
// Coppies rcpfd into the buffer pointed to by pcpfd. The caller is responsible for
// allocating pcpfd. This function uses CoTaskMemAlloc to allocate memory for 
// pcpfd->pszLabel.
//
HRESULT FieldDescriptorCopy(
                            const CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR& rcpfd,
                            CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR* pcpfd
                            )
{
    HRESULT hr;
    CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR cpfd;

    cpfd.dwFieldID = rcpfd.dwFieldID;
    cpfd.cpft = rcpfd.cpft;

    if (rcpfd.pszLabel)
    {
        hr = SHStrDupW(rcpfd.pszLabel, &cpfd.pszLabel);
    }
    else
    {
        cpfd.pszLabel = NULL;
        hr = S_OK;
    }

    if (SUCCEEDED(hr))
    {
        *pcpfd = cpfd;
    }

    return hr;
}


//
// Return a copy of pwzToProtect encrypted with the CredProtect API.
//
// pwzToProtect must not be NULL or the empty string.
//
static HRESULT ProtectAndCopyString(
                                    PWSTR pwzToProtect, 
                                    PWSTR* ppwzProtected
                                    )
{
    *ppwzProtected = NULL;

    HRESULT hr = E_FAIL;

    // The first call to CredProtect determines the length of the encrypted string.
    // Because we pass a NULL output buffer, we expect the call to fail.
    //
    // Note that the third parameter to CredProtect, the number of characters of pwzToProtect
    // to encrypt, must include the NULL terminator!
    DWORD cchProtected = 0;
	PWSTR pwzProtected = L"";
    if (!CredProtectW(FALSE, pwzToProtect, (DWORD)wcslen(pwzToProtect)+1, pwzProtected, &cchProtected, NULL))
    {
        DWORD dwErr = GetLastError();

        if ((ERROR_INSUFFICIENT_BUFFER == dwErr) && (0 < cchProtected))
        {
            // Allocate a buffer long enough for the encrypted string.
            pwzProtected = (PWSTR)CoTaskMemAlloc(cchProtected * sizeof(WCHAR));

            if (pwzProtected)
            {
                // The second call to CredProtect actually encrypts the string.
                if (CredProtectW(FALSE, pwzToProtect, (DWORD)wcslen(pwzToProtect)+1, pwzProtected, &cchProtected, NULL))
                {
                    *ppwzProtected = pwzProtected;
                    hr = S_OK;
                }
                else
                {
                    CoTaskMemFree(pwzProtected);

                    dwErr = GetLastError();
                    hr = HRESULT_FROM_WIN32(dwErr);
                }
            }
            else
            {
                hr = E_OUTOFMEMORY;
            }
        }
        else
        {
            hr = HRESULT_FROM_WIN32(dwErr);
        }
    }

    return hr;
}

//
// If pwzPassword should be encrypted, return a copy encrypted with CredProtect.
// 
// If not, just return a copy.
//
HRESULT ProtectIfNecessaryAndCopyPassword(
                                          PWSTR pwzPassword,
                                          CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus,
										  DWORD dwFlags,
                                          PWSTR* ppwzProtectedPassword
                                          )
{
    *ppwzProtectedPassword = NULL;

    HRESULT hr;

    // ProtectAndCopyString is intended for non-empty strings only.  Empty passwords
    // do not need to be encrypted.
    if (pwzPassword && *pwzPassword)
    {
        bool bCredAlreadyEncrypted = false;
        CRED_PROTECTION_TYPE protectionType;

        // If the password is already encrypted, we should not encrypt it again.
        // An encrypted password may be received through SetSerialization in the 
        // CPUS_LOGON scenario during a Terminal Services connection, for instance.
        if(CredIsProtectedW(pwzPassword, &protectionType))
        {
            if(CredUnprotected != protectionType)
            {
                bCredAlreadyEncrypted = true;
            }
        }

        // Passwords should not be encrypted in the CPUS_CREDUI scenario.  We
        // cannot know if our caller expects or can handle an encryped password.
        if (CPUS_CREDUI == cpus || bCredAlreadyEncrypted || (dwFlags & CREDUIWIN_GENERIC))
        {
            hr = SHStrDupW(pwzPassword, ppwzProtectedPassword);
        }
        else
        {
            hr = ProtectAndCopyString(pwzPassword, ppwzProtectedPassword);
        }
    }
    else
    {
        hr = SHStrDupW(L"", ppwzProtectedPassword);
    }

    return hr;
}
