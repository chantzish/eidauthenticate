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

#include "../EIDCardLibrary/CertificateValidation.h"
#include "../EIDCardLibrary/CertificateUtilities.h"
#include "../EIDCardLibrary/BEID.h"
#include "../EIDCardLibrary/Package.h"
#include "../EIDCardLibrary/Tracing.h"
#include <lm.h>
#include <WinCred.h>


template <typename T> 
CContainerHolderFactory<T>::CContainerHolderFactory()
{
	_cpus = CPUS_INVALID;
	_dwFlags = 0;
	InitializeCriticalSection(&CriticalSection);
}

template <typename T> 
CContainerHolderFactory<T>::~CContainerHolderFactory()
{
	CleanList();
	DeleteCriticalSection(&CriticalSection);
}

template <typename T> 
VOID CContainerHolderFactory<T>::Lock()
{
	EnterCriticalSection(&CriticalSection);
}

template <typename T> 
VOID CContainerHolderFactory<T>::Unlock()
{
	LeaveCriticalSection(&CriticalSection);
}

template <typename T> 
HRESULT CContainerHolderFactory<T>::SetUsageScenario(
    CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus,
    DWORD dwFlags
    )
{
	_cpus = cpus;
	_dwFlags = dwFlags;
	return S_OK;
}

template <typename T> 
BOOL CContainerHolderFactory<T>::ConnectNotification(__in LPCTSTR szReaderName,__in LPCTSTR szCardName, __in USHORT ActivityCount)
{
	if (_tcscmp(szCardName, _TBEIDCardName) == 0)
	{
		return ConnectNotificationBeid(szReaderName,szCardName, ActivityCount);
	}
	else
	{
		return ConnectNotificationGeneric(szReaderName,szCardName, ActivityCount);
	}
}

// called to enumerate the credential built with a CContainer
template <typename T> 
BOOL CContainerHolderFactory<T>::ConnectNotificationGeneric(__in LPCTSTR szReaderName,__in LPCTSTR szCardName, __in USHORT ActivityCount)
{
	HCRYPTPROV HCryptProv,hProv=NULL;
	BOOL bStatus;
	CHAR szContainerName[1024];
	DWORD dwContainerNameLen = 1024;
	TCHAR szProviderName[1024] = TEXT("");
	DWORD dwProviderNameLen = 1024;
	DWORD pKeySpecs[2] = {AT_KEYEXCHANGE,AT_SIGNATURE};
	DWORD dwKeyNumMax = 1;
	HCRYPTKEY hKey;
	// remove existing entries
	//DisconnectNotification(szReaderName);
	EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Connect Reader %s CardName %s",szReaderName,szCardName);
	// get provider name
	if (!SchGetProviderNameFromCardName(szCardName, szProviderName, &dwProviderNameLen))
	{
		return FALSE;
	}

	size_t ulNameLen = _tcslen(szReaderName);
	LPTSTR szMainContainerName = (LPTSTR) malloc(sizeof(TCHAR)*(ulNameLen + 6));
	if (!szMainContainerName)
	{
		EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"szMainContainerName %d",GetLastError());
		return FALSE;
	}
	_stprintf_s(szMainContainerName,(ulNameLen + 6), _T("\\\\.\\%s\\"), szReaderName);
	
	// if policy 
	if (GetPolicyValue(AllowSignatureOnlyKeys))
	{
		dwKeyNumMax = 2;
	}


	bStatus = CryptAcquireContext(&HCryptProv,
				szMainContainerName,
				szProviderName,
				PROV_RSA_FULL,
				CRYPT_SILENT);
	if (!bStatus)
	{
		EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"CryptAcquireContext 0x%08x",GetLastError());
		return FALSE;
	}
	DWORD dwFlags = CRYPT_FIRST;
	/* Enumerate all the containers */
	while (CryptGetProvParam(HCryptProv,
				PP_ENUMCONTAINERS,
				(LPBYTE) szContainerName,
				&dwContainerNameLen,
				dwFlags)
			)
	{
		// convert the container name to unicode
#ifdef UNICODE
		int wLen = MultiByteToWideChar(CP_ACP, 0, szContainerName, -1, NULL, 0);
		LPTSTR szWideContainerName = (LPTSTR) malloc(sizeof(TCHAR)*wLen);
		if (szWideContainerName)
		{
			MultiByteToWideChar(CP_ACP, 0, szContainerName, -1, szWideContainerName, wLen);
#else
		LPTSTR szWideContainerName = (LPTSTR) malloc(sizeof(TCHAR)*(_tcslen(szContainerName)+1));
		if (szWideContainerName)
			{
			_tcscpy_s(szWideContainerName,_tcslen(szContainerName)+1,szContainerName);

#endif
			// create a CContainer item
			if (CryptAcquireContext(&hProv,
				szWideContainerName,
				szProviderName,
				PROV_RSA_FULL,
				CRYPT_SILENT))
			{
				for (DWORD i = 0; i < dwKeyNumMax; i++)
				{
					if (CryptGetUserKey(hProv,
							pKeySpecs[i],
							&hKey) )
					{
						BYTE Data[4096];
						DWORD DataSize = 4096;
						if (CryptGetKeyParam(hKey,
								KP_CERTIFICATE,
								Data,
								&DataSize,
								0))
						{
							CreateItemFromCertificateBlob(szReaderName,szCardName,szProviderName,
								szWideContainerName, pKeySpecs[i],ActivityCount, Data, DataSize);
						}
						CryptDestroyKey(hKey);
						hKey = NULL;
					}
				}
			}
			CryptReleaseContext(hProv, 0);
			hProv = NULL;
		}
		dwFlags = CRYPT_NEXT;
		dwContainerNameLen = 1024;
		free(szWideContainerName);
	}
	CryptReleaseContext(HCryptProv,0);
	free(szMainContainerName);
	return TRUE;
}

template <typename T> 
BOOL CContainerHolderFactory<T>::ConnectNotificationBeid(__in LPCTSTR szReaderName,__in LPCTSTR szCardName, __in USHORT ActivityCount)
{
	PBYTE pbData = NULL;
	DWORD dwSize;
	TCHAR szProviderName[1024];
	DWORD dwProviderNameLen = 1024;
	LPTSTR szContainerName = NULL;
	DWORD dwKeySpec = 0;
	
	// get provider name
	if (!SchGetProviderNameFromCardName(szCardName, szProviderName, &dwProviderNameLen))
	{
		return FALSE;
	}

	if (GetBEIDCertificateData(szReaderName, &szContainerName,&dwKeySpec, &pbData,&dwSize))
	{
		CreateItemFromCertificateBlob(szReaderName,szCardName,szProviderName,
									szContainerName, dwKeySpec,ActivityCount, pbData, dwSize);
		if (szContainerName) 
			free(szContainerName);
		if (pbData)
			free(pbData);
	}

	return TRUE;
}

template <typename T>
BOOL CContainerHolderFactory<T>::CreateItemFromCertificateBlob(__in LPCTSTR szReaderName,__in LPCTSTR szCardName,
															   __in LPCTSTR szProviderName, __in LPCTSTR szWideContainerName,
															   __in DWORD KeySpec, __in USHORT ActivityCount,
															   __in PBYTE Data, __in DWORD DataSize)
{
	BOOL fReturn = FALSE;
	PCCERT_CONTEXT pCertContext = NULL;
	pCertContext = CertCreateCertificateContext(X509_ASN_ENCODING, Data, DataSize);
	if (pCertContext)
	{
		BOOL fAdd = TRUE;
		CRYPT_KEY_PROV_INFO KeyProvInfo;
		KeyProvInfo.dwFlags = 0;
		KeyProvInfo.dwKeySpec = KeySpec;
		KeyProvInfo.dwProvType = PROV_RSA_FULL;
		KeyProvInfo.pwszContainerName = (LPTSTR) szWideContainerName;
		KeyProvInfo.pwszProvName = (LPTSTR) szProviderName;
		KeyProvInfo.rgProvParam = 0;
		KeyProvInfo.cProvParam = NULL;
		CContainer* pContainer = NULL;
		CertSetCertificateContextProperty(pCertContext, CERT_KEY_PROV_INFO_PROP_ID, 0, &KeyProvInfo);

		if (_cpus != CPUS_CREDUI)
		{
			fAdd = IsTrustedCertificate(pCertContext);
			if (!fAdd)
			{
				EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Untrusted certificate 0x%x",GetLastError());
			}
		}
		if (fAdd)
		{
			pContainer = new CContainer(szReaderName,szCardName,szProviderName,szWideContainerName, KeySpec, ActivityCount, pCertContext);
			// check if the Container meet the requirement
			PTSTR UserName = pContainer->GetUserName();
			if (UserName)
			{
				if ((_cpus == CPUS_LOGON || _cpus == CPUS_UNLOCK_WORKSTATION) && fAdd)
				{
					fAdd = HasAccountOnCurrentComputer(UserName);
					if (!fAdd)
					{
						EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"HasAccountOnCurrentComputer 0x%x",GetLastError());
					}
				}
				if (((_dwFlags & CREDUIWIN_ENUMERATE_CURRENT_USER) || (_cpus == CPUS_UNLOCK_WORKSTATION)) && fAdd)
				{
					fAdd = IsCurrentUser(UserName);
					if (!fAdd)
					{
						EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"IsCurrentUser 0x%x",GetLastError());
					}
				}
				if ((_dwFlags & CREDUIWIN_ENUMERATE_ADMINS) && fAdd)
				{
					fAdd = IsAdmin(UserName);
					if (!fAdd)
					{
						EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"IsAdmin 0x%x",GetLastError());
					}
				}
			}
			else
			{
				fAdd = FALSE;
			}
		}
		if (fAdd)
		{
			this->Lock();
			T* ContainerHolder = new T(pContainer);
			ContainerHolder->SetUsageScenario(_cpus, _dwFlags);
			_CredentialList.push_back(ContainerHolder);
			this->Unlock();
			fReturn = TRUE;
		}
		else
		{
			if (pContainer)
				delete pContainer;
		}
	}
	else
	{
		EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Unable to CertCreateCertificateContext : %d",GetLastError());
	}
	return fReturn;
}

template <typename T> 
BOOL CContainerHolderFactory<T>::DisconnectNotification(LPCTSTR szReaderName)
{
	std::list<T*>::iterator l_iter = _CredentialList.begin();
	while(l_iter!=_CredentialList.end())
	{
		T* item = (T *)*l_iter;
		CContainer* container = item->GetContainer();

#ifndef UNICODE
		int wLen = MultiByteToWideChar(CP_ACP, 0, szReaderName, -1, NULL, 0);
		LPWSTR szWideReaderName = (LPWSTR) malloc(sizeof(WCHAR)*wLen);
		if (szWideReaderName)
		{
			MultiByteToWideChar(CP_ACP, 0, szReaderName, -1, szWideReaderName, wLen);
#else
		LPWSTR szWideReaderName = (LPWSTR) malloc(sizeof(WCHAR)*(_tcslen(szReaderName)+1));
		if (szWideReaderName)
			{
			_tcscpy_s(szWideReaderName,_tcslen(szReaderName)+1,szReaderName);

#endif
			if(container->IsOnReader(szWideReaderName))
			{
				l_iter = _CredentialList.erase(l_iter);
				//delete item;
				item->Release();
			}
			else
			{
				++l_iter;
			}
			free(szWideReaderName);
		}
	}
	return TRUE;
}

template <typename T> 
BOOL CContainerHolderFactory<T>::CleanList()
{
	std::list<T*>::iterator l_iter = _CredentialList.begin();
	while(l_iter!=_CredentialList.end())
	{
		T* item = (T *)*l_iter;
		l_iter = _CredentialList.erase(l_iter);
		item->Release();
	}
	return TRUE;
}

template <typename T> 
BOOL CContainerHolderFactory<T>::HasContainerHolder()
{
	return _CredentialList.size()>0;
}


template <typename T> 
DWORD CContainerHolderFactory<T>::ContainerHolderCount()
{
	return (DWORD) _CredentialList.size();
}

template <typename T> 
T* CContainerHolderFactory<T>::GetContainerHolderAt(DWORD dwIndex)
{
	if (dwIndex >= _CredentialList.size())
	{
		return NULL;
	}
	std::list<T*>::iterator it = _CredentialList.begin();
	std::advance(it, dwIndex);
	return *it;
}