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

BOOL CreateStoredCredential(__in DWORD dwRid,  __in PWSTR szPassword, __in_opt USHORT dwPasswordLen,
							__in PCWSTR szProvider, __in PCWSTR szContainer, __in DWORD dwKeySpec);


BOOL UpdateStoredCredential(__in DWORD dwRid, __in PWSTR szPassword, __in_opt USHORT usPasswordLen);
BOOL UpdateStoredCredentialEx(__in DWORD dwRid, __in PWSTR szPassword, __in_opt USHORT usPasswordLen,
							__in_opt PBYTE pPublicKeyBlob, __in_opt USHORT usPublicKeySize, __in_opt BOOL fEncryptPassword);


BOOL RetrieveStoredCredential(__in DWORD dwRid, __in PCCERT_CONTEXT pCertContext, __in LPCTSTR Pin, __out PWSTR *pszPassword);

BOOL RemoveStoredCredential(__in DWORD dwRid);
BOOL CanEncryptPassword(__in_opt HCRYPTPROV hProv, __in_opt DWORD dwKeySpec,  __in_opt PCCERT_CONTEXT pCertContext);

BOOL HasStoredCredential(__in DWORD dwRid);

NTSTATUS CheckPassword( __in DWORD dwRid, __in PWSTR szPassword);

BOOL GetPublicKeyBlobFromCertificate(PCCERT_CONTEXT pCertContext, PBYTE *ppbPublicKey);

#ifdef _NTSECPKG_
NTSTATUS CompletePrimaryCredential(__in PLSA_UNICODE_STRING AuthenticatingAuthority,
						__in PLSA_UNICODE_STRING AccountName,
						__in PSID UserSid,
						__in PLUID LogonId,
						__in PWSTR szPassword,
						__in PLSA_DISPATCH_TABLE FunctionTable,
						__out  PSECPKG_PRIMARY_CRED PrimaryCredentials);
#endif