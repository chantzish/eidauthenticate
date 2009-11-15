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


#define _TBEIDCardName TEXT("Belgium Electronic ID card")
#define WBEIDCardName L"Belgium Electronic ID card"
#define WBEIDCSP L"Belgium Identity Card CSP"
#define TBEIDCSP TEXT("Belgium Identity Card CSP")


BOOL GetBEIDCertificateData(__in LPCTSTR szReaderName,__out LPTSTR *pszContainerName,
							__out PDWORD pdwKeySpec, __out PBYTE *ppbData, __out PDWORD pdwCount,
							__in_opt DWORD dwKeySpec = 0);
PCCERT_CONTEXT GetBEIDCertificateFromCspInfo(__in PEID_SMARTCARD_CSP_INFO pCspInfo);
BOOL SolveBEIDChallenge(__in PCCERT_CONTEXT pCertContext, __in LPCWSTR Pin);

