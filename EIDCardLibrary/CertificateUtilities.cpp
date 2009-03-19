#include <windows.h>
#include <tchar.h>
#include <Cryptuiapi.h>
#include <AccCtrl.h>
#include <Aclapi.h>
#include "CertificateUtilities.h"
#include "Tracing.h"


#pragma comment (lib,"Scarddlg")
#pragma comment (lib,"Rpcrt4")


BOOL SchGetProviderNameFromCardName(__in LPCTSTR szCardName, __out LPTSTR szProviderName, __out PDWORD pdwProviderNameLen)
{
	// get provider name
	SCARDCONTEXT hSCardContext;
	LONG lCardStatus;
	lCardStatus = SCardEstablishContext(SCARD_SCOPE_USER,NULL,NULL,&hSCardContext);
	if (SCARD_S_SUCCESS != lCardStatus)
	{
		EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"SCardEstablishContext 0x%08x",lCardStatus);
		return FALSE;
	}
	
	lCardStatus = SCardGetCardTypeProviderName(hSCardContext,
									   szCardName,
									   SCARD_PROVIDER_CSP,
									   szProviderName,
									   pdwProviderNameLen);
	if (SCARD_S_SUCCESS != lCardStatus)
	{
		EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"SCardGetCardTypeProviderName 0x%08x",lCardStatus);
		SCardReleaseContext(hSCardContext);
		return FALSE;
	}
	SCardReleaseContext(hSCardContext);
	return TRUE;
}

// the string must be freed using RpcStringFree
LPTSTR GetUniqueIDString()
{
	UUID pUUID;
	LPTSTR sTemp = NULL;
	RPC_STATUS hr;
	hr = UuidCreateSequential(&pUUID);
	if (hr == RPC_S_OK)
	{
        hr = UuidToString(&pUUID, (RPC_WSTR *)&sTemp); 
	}
	return sTemp;
}

PCCERT_CONTEXT SelectCertificateWithPrivateKey(HWND hWnd)
{
	PCCERT_CONTEXT returnedContext = NULL;
		
	HCERTSTORE hCertStore,hStore;
	BOOL bShowNoCertificate = TRUE;
	// open trusted root store
	hCertStore = CertOpenStore(CERT_STORE_PROV_SYSTEM,0,NULL,CERT_SYSTEM_STORE_CURRENT_USER,_T("Root"));
	if (hCertStore)
	{
		PCCERT_CONTEXT pCertContext = NULL;
		PBYTE dwKeySpec = NULL;
		DWORD dwSize = 0;
		// open a temp store and copy context which have a private key
		hStore = CertOpenStore(CERT_STORE_PROV_MEMORY,X509_ASN_ENCODING,NULL,0,	NULL);

		if (hStore)
		{
			pCertContext = CertEnumCertificatesInStore(hCertStore,pCertContext);
			while (pCertContext)
			{
				
				if (CertGetCertificateContextProperty(pCertContext,CERT_KEY_PROV_INFO_PROP_ID,dwKeySpec,&dwSize))
				{
					//The certificate has a private key
					CertAddCertificateContextToStore(hStore,pCertContext,CERT_STORE_ADD_USE_EXISTING,NULL);
					bShowNoCertificate = FALSE;
				}
				pCertContext = CertEnumCertificatesInStore(hCertStore,pCertContext);
			}
			if (bShowNoCertificate)
			{
				MessageBox(hWnd,_T("No Trusted certificate found"),_T("Warning"),0);
			}
			else
			{
				returnedContext = CryptUIDlgSelectCertificateFromStore(
					  hStore,
					  NULL,
					  NULL,
					  NULL,
					  CRYPTUI_SELECT_LOCATION_COLUMN,
					  0,
					  NULL);
			}
			CertCloseStore(hStore,0);
		}
		CertCloseStore(hCertStore,0);
	}
	return returnedContext;
}

PCCERT_CONTEXT SelectFirstCertificateWithPrivateKey()
{
	PCCERT_CONTEXT returnedContext = NULL;
		
	HCERTSTORE hCertStore = NULL;
	// open trusted root store
	hCertStore = CertOpenStore(CERT_STORE_PROV_SYSTEM,0,NULL,CERT_SYSTEM_STORE_CURRENT_USER,_T("Root"));
	if (hCertStore)
	{
		PCCERT_CONTEXT pCertContext = NULL;
		pCertContext = CertEnumCertificatesInStore(hCertStore,pCertContext);
		while (pCertContext)
		{
			
			PBYTE KeySpec = NULL;
			DWORD dwSize = 0;
			if (CertGetCertificateContextProperty(pCertContext,CERT_KEY_PROV_INFO_PROP_ID,KeySpec,&dwSize))
			{
				//The certificate has a private key
				returnedContext = pCertContext;
				break;
			}
			pCertContext = CertEnumCertificatesInStore(hCertStore,pCertContext);
		}
		CertCloseStore(hCertStore,0);
	}
	return returnedContext;
}


LPBYTE AllocateAndEncodeObject(LPVOID pvStruct, LPCSTR lpszStructType, LPDWORD pdwSize )
{
   // Get Key Usage blob size   
   LPBYTE pbEncodedObject = NULL;
   BOOL bResult = TRUE;
   DWORD dwError;
	__try
   {
	   *pdwSize = 0;	
	   bResult = CryptEncodeObject(X509_ASN_ENCODING,   
								   lpszStructType,   
								   pvStruct,   
								   NULL, pdwSize);   
	   if (!bResult)   
	   {   
		  dwError = GetLastError();
		  __leave;   
	   }   

	   // Allocate Memory for Key Usage Blob   
	   pbEncodedObject = (LPBYTE)malloc(*pdwSize);   
	   if (!pbEncodedObject)   
	   {   
		  bResult = FALSE;
		  dwError = GetLastError();   
		  __leave;   
	   }   

	   // Get Key Usage Extension blob   
	   bResult = CryptEncodeObject(X509_ASN_ENCODING,   
								   lpszStructType,   
								   pvStruct,   
								   pbEncodedObject, pdwSize);   
	   if (!bResult)   
	   {   
		  dwError = GetLastError();  
		  __leave;   
	   }   
   }
   __finally
   {
		if (pbEncodedObject && !bResult)
		{
			free(pbEncodedObject);
		}
   }
   return pbEncodedObject;
}

BOOL AskForCard(LPWSTR szReader, DWORD ReaderLength,LPWSTR szCard,DWORD CardLength)
{
	SCARDCONTEXT     hSC;
	OPENCARDNAME_EX  dlgStruct;
	LONG             lReturn;
	DWORD dwErr = 0;
	// Establish a context.
	// It will be assigned to the structure's hSCardContext field.
	lReturn = SCardEstablishContext(SCARD_SCOPE_USER,
									NULL,
									NULL,
									&hSC );
	if ( SCARD_S_SUCCESS != lReturn )
	{
		EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Failed SCardReleaseContext 0x%08X",lReturn);
		return FALSE;
	}

	// Initialize the structure.
	memset(&dlgStruct, 0, sizeof(dlgStruct));
	dlgStruct.dwStructSize = sizeof(dlgStruct);
	dlgStruct.hSCardContext = hSC;
	dlgStruct.dwFlags = SC_DLG_MINIMAL_UI;
	dlgStruct.lpstrRdr = szReader;
	dlgStruct.nMaxRdr = ReaderLength;
	dlgStruct.lpstrCard = szCard;
	dlgStruct.nMaxCard = CardLength;
	dlgStruct.lpstrTitle = L"Select Card";
	dlgStruct.dwShareMode = 0;
	// Display the select card dialog box.
	lReturn = SCardUIDlgSelectCard(&dlgStruct);
	if ( SCARD_S_SUCCESS != lReturn )
	{
		szReader[0]=0;
		szCard[0]=0;
		dwErr = 1;
		MessageBox(NULL,L"No reader available",L"",0);
	}

	// Free the context.
	// lReturn is of type LONG.
	// hSC was set by an earlier call to SCardEstablishContext.
	lReturn = SCardReleaseContext(hSC);
	if ( SCARD_S_SUCCESS != lReturn )
		EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Failed SCardReleaseContext 0x%08X",lReturn);
	return dwErr==0;
}

BOOL CreateCertificate(PUI_CERTIFICATE_INFO pCertificateInfo)
{
	BOOL fReturn = FALSE;
	CERT_INFO CertInfo = {0};
	CertInfo.rgExtension = 0;
	CERT_NAME_BLOB SubjectIssuerBlob = {0};
	HCRYPTPROV hCryptProvNewCertificate = NULL, hCryptProvRootCertificate = NULL;
	PCCERT_CONTEXT pNewCertificateContext = NULL;
	PCERT_PUBLIC_KEY_INFO pbPublicKeyInfo = NULL;
	HCERTSTORE hCertStore = NULL;
	PBYTE  pbSignedEncodedCertReq = NULL;
	BOOL bDestroyContainer = FALSE;
	HCRYPTKEY hKey = NULL;
	CRYPT_KEY_PROV_INFO KeyProvInfo = {0};
	LPTSTR szContainerName=NULL;
    FILETIME ftTime;   
	BYTE SerialNumber[8];  
	DWORD dwKeyType = 0;
	DWORD cbPublicKeyInfo = 0;
	BOOL pfCallerFreeProvOrNCryptKey;
	CRYPT_ALGORITHM_IDENTIFIER SigAlg;
	CRYPT_OBJID_BLOB  Parameters;
	CRYPTUI_WIZ_EXPORT_INFO WizInfo = {0};
	DWORD cbEncodedCertReqSize = 0;
	TCHAR szProviderName[1024];
	DWORD dwProviderNameLen = 1024;
	DWORD dwFlag;
	DWORD dwSize;
	HCRYPTHASH hHash = 0;  
    BYTE ByteData;   
    CRYPT_BIT_BLOB KeyUsage;   
	LPBYTE pbKeyUsage = NULL; 
	LPBYTE pbBasicConstraints = NULL;
	LPBYTE pbEnhKeyUsage = NULL;
	LPBYTE pbKeyIdentifier = NULL;   
	LPBYTE SubjectKeyIdentifier = NULL;   
	CRYPT_DATA_BLOB CertKeyIdentifier;
	CERT_BASIC_CONSTRAINTS2_INFO BasicConstraints;
	CERT_ENHKEY_USAGE CertEnhKeyUsage = { 0, NULL };  
	CERT_EXTENSIONS CertExtensions = {0} ;
	DWORD dwError = 0;
	PSID pSidSystem = NULL;
	PSID pSidAdmins = NULL;
	PACL pDacl = NULL;
	SID_IDENTIFIER_AUTHORITY sia = SECURITY_NT_AUTHORITY;
	PSECURITY_DESCRIPTOR pSD = NULL;
	__try   
    { 

		pCertificateInfo->pNewCertificate = NULL;
		// prepare the container name based on the support
		if (pCertificateInfo->dwSaveon == UI_CERTIFICATE_INFO_SAVEON_SMARTCARD)
		{
			// provider name
			if (!SchGetProviderNameFromCardName(pCertificateInfo->szCard, szProviderName, &dwProviderNameLen))
			{
				__leave;
			}
			// container name from card name
			size_t ulNameLen = _tcslen(pCertificateInfo->szReader);
			szContainerName = (LPTSTR) LocalAlloc(0, (ulNameLen + 6) * sizeof(TCHAR));
			if (!szContainerName)
			{
				dwError = GetLastError();
				__leave;
			}
			_stprintf_s(szContainerName,(ulNameLen + 6), _T("\\\\.\\%s\\"), pCertificateInfo->szReader);
		}
		else
		{
			// container name = GUID
			szContainerName = GetUniqueIDString();
			if (!szContainerName) __leave;
			// Provider  MS_ENHANCED_PROV
			_stprintf_s(szProviderName,1024,_T("%s"),MS_ENHANCED_PROV);
		}

			
		dwFlag=CRYPT_NEWKEYSET;
		switch(pCertificateInfo->dwSaveon)
		{
			case UI_CERTIFICATE_INFO_SAVEON_SYSTEMSTORE: // machine
			case UI_CERTIFICATE_INFO_SAVEON_SMARTCARD: // smart card
				dwFlag |= CRYPT_MACHINE_KEYSET;
		}
		// create container
		if (!CryptAcquireContext(
			&hCryptProvNewCertificate,
			szContainerName,          
			szProviderName,           
			PROV_RSA_FULL,      
			dwFlag))   
		{
			dwError = GetLastError();
			__leave;
		}
		else
		{
			bDestroyContainer=TRUE;
		}
		// generate key
		dwFlag=0;
		switch(pCertificateInfo->dwSaveon)
		{
			case UI_CERTIFICATE_INFO_SAVEON_USERSTORE: // user
			case UI_CERTIFICATE_INFO_SAVEON_SYSTEMSTORE: // machine
			case UI_CERTIFICATE_INFO_SAVEON_FILE: // file
				dwFlag |= CRYPT_EXPORTABLE;
		}
		if (!CryptGenKey(hCryptProvNewCertificate, pCertificateInfo->dwKeyType, dwFlag, &hKey))
		{
			dwError = GetLastError();
			__leave;
		}

		
		// create the cert data
		if (!CertStrToName(X509_ASN_ENCODING,pCertificateInfo->szSubject,CERT_X500_NAME_STR,NULL,NULL,&SubjectIssuerBlob.cbData,NULL))
		{
			dwError = GetLastError();
			__leave;
		}
		SubjectIssuerBlob.pbData = (PBYTE) malloc(SubjectIssuerBlob.cbData);
		if (!SubjectIssuerBlob.pbData)
		{
			dwError = GetLastError();
			__leave;
		}
		if (!CertStrToName(X509_ASN_ENCODING,pCertificateInfo->szSubject,CERT_X500_NAME_STR,NULL,(PBYTE)SubjectIssuerBlob.pbData,&SubjectIssuerBlob.cbData,NULL))
		{
			dwError = GetLastError();
			__leave;
		}

		//////////////////////////////////////////////////
		// Key Usage & ...
		
		// max 10 extensions => we don't count them
		CertInfo.rgExtension = (PCERT_EXTENSION) malloc(sizeof(CERT_EXTENSION) * 10);
		CertInfo.cExtension = 0;
		if (!CertInfo.rgExtension) __leave;


		       // Set Key Usage according to Public Key Type   
       ZeroMemory(&KeyUsage, sizeof(KeyUsage));   
       KeyUsage.cbData = 1;   
       KeyUsage.pbData = &ByteData;   
    
       if (pCertificateInfo->dwKeyType == AT_SIGNATURE)   
       {   
          ByteData = CERT_DIGITAL_SIGNATURE_KEY_USAGE|   
                     CERT_NON_REPUDIATION_KEY_USAGE|   
                     CERT_KEY_CERT_SIGN_KEY_USAGE |   
                     CERT_CRL_SIGN_KEY_USAGE;   
       }   
    
       if (pCertificateInfo->dwKeyType == AT_KEYEXCHANGE)   
       {   
          ByteData = CERT_DIGITAL_SIGNATURE_KEY_USAGE |   
                     CERT_DATA_ENCIPHERMENT_KEY_USAGE|   
                     CERT_KEY_ENCIPHERMENT_KEY_USAGE |   
                     CERT_KEY_AGREEMENT_KEY_USAGE;   
       }


		pbKeyUsage = AllocateAndEncodeObject(&KeyUsage,X509_KEY_USAGE,&dwSize);
		if (!pbKeyUsage) __leave;

		CertInfo.rgExtension[CertInfo.cExtension].pszObjId = szOID_KEY_USAGE;   
		CertInfo.rgExtension[CertInfo.cExtension].fCritical = FALSE;   
		CertInfo.rgExtension[CertInfo.cExtension].Value.cbData = dwSize;   
		CertInfo.rgExtension[CertInfo.cExtension].Value.pbData = pbKeyUsage;   
       // Increase extension count   
       CertInfo.cExtension++; 
	   //////////////////////////////////////////////////

	   // Zero Basic Constraints structure   
       ZeroMemory(&BasicConstraints, sizeof(BasicConstraints));   
    
       // Self-signed is always a CA   
       if (pCertificateInfo->bIsSelfSigned)   
       {   
          BasicConstraints.fCA = TRUE;   
          BasicConstraints.fPathLenConstraint = TRUE;   
          BasicConstraints.dwPathLenConstraint = 1;   
       }   
       else   
       {   
          BasicConstraints.fCA = pCertificateInfo->bIsCA;   
       }   
		pbBasicConstraints = AllocateAndEncodeObject(&BasicConstraints,X509_BASIC_CONSTRAINTS2,&dwSize);
		if (!pbBasicConstraints) __leave;

       // Set Basic Constraints extension   
       CertInfo.rgExtension[CertInfo.cExtension].pszObjId = szOID_BASIC_CONSTRAINTS2;   
       CertInfo.rgExtension[CertInfo.cExtension].fCritical = FALSE;   
       CertInfo.rgExtension[CertInfo.cExtension].Value.cbData = dwSize;   
       CertInfo.rgExtension[CertInfo.cExtension].Value.pbData = pbBasicConstraints;   
       // Increase extension count   
       CertInfo.cExtension++;  
		//////////////////////////////////////////////////
		if (pCertificateInfo->bHasClientAuthentication)
			CertEnhKeyUsage.cUsageIdentifier++;
		if (pCertificateInfo->bHasServerAuthentication)
			CertEnhKeyUsage.cUsageIdentifier++;
		if (pCertificateInfo->bHasSmartCardAuthentication)
			CertEnhKeyUsage.cUsageIdentifier++;
		if (pCertificateInfo->bHasEFS)
			CertEnhKeyUsage.cUsageIdentifier++;


		if (CertEnhKeyUsage.cUsageIdentifier != 0)   
		{
			CertEnhKeyUsage.rgpszUsageIdentifier = (LPSTR*) malloc(sizeof(LPSTR)*CertEnhKeyUsage.cUsageIdentifier);
			if (!CertEnhKeyUsage.rgpszUsageIdentifier) __leave;
			CertEnhKeyUsage.cUsageIdentifier = 0;
			if (pCertificateInfo->bHasClientAuthentication)
				CertEnhKeyUsage.rgpszUsageIdentifier[CertEnhKeyUsage.cUsageIdentifier++] = szOID_PKIX_KP_CLIENT_AUTH;
			if (pCertificateInfo->bHasServerAuthentication)
				CertEnhKeyUsage.rgpszUsageIdentifier[CertEnhKeyUsage.cUsageIdentifier++] = szOID_PKIX_KP_SERVER_AUTH;
			if (pCertificateInfo->bHasSmartCardAuthentication)
				CertEnhKeyUsage.rgpszUsageIdentifier[CertEnhKeyUsage.cUsageIdentifier++] = szOID_KP_SMARTCARD_LOGON;
			if (pCertificateInfo->bHasEFS)
				CertEnhKeyUsage.rgpszUsageIdentifier[CertEnhKeyUsage.cUsageIdentifier++] = szOID_KP_EFS;
			pbEnhKeyUsage = AllocateAndEncodeObject(&CertEnhKeyUsage,X509_ENHANCED_KEY_USAGE,&dwSize);
			if (!pbEnhKeyUsage) __leave;

		   // Set Basic Constraints extension   
		   CertInfo.rgExtension[CertInfo.cExtension].pszObjId = szOID_ENHANCED_KEY_USAGE;   
		   CertInfo.rgExtension[CertInfo.cExtension].fCritical = FALSE;   
		   CertInfo.rgExtension[CertInfo.cExtension].Value.cbData = dwSize;   
		   CertInfo.rgExtension[CertInfo.cExtension].Value.pbData = pbEnhKeyUsage;   
		   	// Increase extension count   
			CertInfo.cExtension++; 
		}
 
		//////////////////////////////////////////////////

		if (pCertificateInfo->bIsSelfSigned)
		{
			CertExtensions.cExtension = CertInfo.cExtension;
			CertExtensions.rgExtension = CertInfo.rgExtension;
			pNewCertificateContext = CertCreateSelfSignCertificate(hCryptProvNewCertificate,&SubjectIssuerBlob,
				0,NULL,NULL,&pCertificateInfo->StartTime,&pCertificateInfo->EndTime,&CertExtensions);
			if (!pNewCertificateContext)
			{
				dwError = GetLastError();
				__leave;
			}
		}
		else
		{
			CertInfo.Subject = SubjectIssuerBlob;
			CertInfo.dwVersion = CERT_V3;

			// set issuer info
			CertInfo.Issuer = pCertificateInfo->pRootCertificate->pCertInfo->Subject;
			CertInfo.IssuerUniqueId = pCertificateInfo->pRootCertificate->pCertInfo->SubjectUniqueId;

			
			SystemTimeToFileTime(&pCertificateInfo->StartTime, &ftTime);   
			CertInfo.NotBefore = ftTime;  

			SystemTimeToFileTime(&pCertificateInfo->EndTime, &ftTime);   
			CertInfo.NotAfter = ftTime;   

			// Create Random Serial Number   
			if (!CryptGenRandom(hCryptProvNewCertificate, 8, SerialNumber))   
			{   
				dwError = GetLastError();
				__leave;
			}   

			// Set Serial Number of Certificate   
			CertInfo.SerialNumber.cbData = 8;   
			CertInfo.SerialNumber.pbData = SerialNumber;   
			
			// public key
			//////////////
			if(!CryptExportPublicKeyInfo(
				  hCryptProvNewCertificate,
				  pCertificateInfo->dwKeyType,  
				  X509_ASN_ENCODING,      
				  pbPublicKeyInfo,       
				  &cbPublicKeyInfo))     
			{
				dwError = GetLastError();
				__leave;	
			}
			pbPublicKeyInfo = (PCERT_PUBLIC_KEY_INFO) malloc(cbPublicKeyInfo);
			if (!pbPublicKeyInfo) {
				dwError = GetLastError();
				__leave;
			}
			if(!CryptExportPublicKeyInfo(
				  hCryptProvNewCertificate,
				  pCertificateInfo->dwKeyType,   
				  X509_ASN_ENCODING,      
				  pbPublicKeyInfo,       
				  &cbPublicKeyInfo))     
			{
				dwError = GetLastError();
				__leave;
			}
			CertInfo.SubjectPublicKeyInfo = *pbPublicKeyInfo;
			// Create Hash     
			if (!CryptCreateHash(hCryptProvNewCertificate, CALG_SHA1, 0, 0, &hHash))   
			{   
			  dwError = GetLastError();
			  __leave;   
			}   

			// Hash Public Key Info   
			if (!CryptHashData(hHash, (LPBYTE)pbPublicKeyInfo, dwSize, 0))   
			{   
			  dwError = GetLastError();
			  __leave;   
			}   

			// Get Size of Hash   
			if (!CryptGetHashParam(hHash, HP_HASHVAL, NULL, &dwSize, 0))   
			{   
			  dwError = GetLastError();
			  __leave;   
			}   

			// Allocate Memory for Key Identifier (hash of Public Key info)   
			pbKeyIdentifier = (LPBYTE)malloc(dwSize);   
			if (!pbKeyIdentifier)   
			{   
			  dwError = GetLastError();
			  __leave;   
			}   

			// Get Hash of Public Key Info   
			if (!CryptGetHashParam(hHash, HP_HASHVAL, pbKeyIdentifier, &dwSize, 0))   
			{   
			  dwError = GetLastError();
			  __leave;   
			}   

			// We will use this to set the Key Identifier extension   
			CertKeyIdentifier.cbData = dwSize;   
			CertKeyIdentifier.pbData = pbKeyIdentifier;  

			// Get Subject Key Identifier Extension size   
			if (!CryptEncodeObject(X509_ASN_ENCODING,   
									   szOID_SUBJECT_KEY_IDENTIFIER,   
									   (LPVOID)&CertKeyIdentifier,   
									   NULL, &dwSize))
			{   
			  dwError = GetLastError();
			  __leave;   
			}   

			// Allocate Memory for Subject Key Identifier Blob   
			SubjectKeyIdentifier = (LPBYTE)malloc(dwSize);   
			if (!SubjectKeyIdentifier)   
			{   
			  dwError = GetLastError();
			  __leave;   
			}   

			// Get Subject Key Identifier Extension   
			if (!CryptEncodeObject(X509_ASN_ENCODING,   
									   szOID_SUBJECT_KEY_IDENTIFIER,   
									   (LPVOID)&CertKeyIdentifier,   
									   SubjectKeyIdentifier, &dwSize))
			{   
			  dwError = GetLastError();
			  __leave;   
			}   

			// Set Subject Key Identifier   
			CertInfo.rgExtension[CertInfo.cExtension].pszObjId = szOID_SUBJECT_KEY_IDENTIFIER;   
			CertInfo.rgExtension[CertInfo.cExtension].fCritical = FALSE;   
			CertInfo.rgExtension[CertInfo.cExtension].Value.cbData = dwSize;   
			CertInfo.rgExtension[CertInfo.cExtension].Value.pbData = SubjectKeyIdentifier;   

			// Increase extension count   
			CertInfo.cExtension++;   
////////////////////////////////////////////////////////////////////////////////////////////////////////
			// sign certificate
			///////////////////
			memset(&Parameters, 0, sizeof(Parameters));
			SigAlg.pszObjId = szOID_OIWSEC_sha1RSASign;
			SigAlg.Parameters = Parameters;

			CertInfo.SignatureAlgorithm = SigAlg;

			// retrieve crypt context from root cert
			if (!CryptAcquireCertificatePrivateKey(pCertificateInfo->pRootCertificate,0,NULL,
					&hCryptProvRootCertificate,&dwKeyType,&pfCallerFreeProvOrNCryptKey))
			{
				dwError = GetLastError();
				//MessageBox(0,_T("need admin privilege ?"),_T("test"),0);
				__leave;
			}
			// sign certificate
			if(!CryptSignAndEncodeCertificate(
				  hCryptProvRootCertificate,                     // Crypto provider
				  AT_SIGNATURE,                 // Key spec
				  X509_ASN_ENCODING,               // Encoding type
				  X509_CERT_TO_BE_SIGNED, // Struct type
				  &CertInfo,                   // Struct info        
				  &SigAlg,                        // Signature algorithm
				  NULL,                           // Not used
				  pbSignedEncodedCertReq,         // Pointer
				  &cbEncodedCertReqSize))         // Length of the message
			{
				dwError = GetLastError();
				__leave;
			}
			pbSignedEncodedCertReq = (PBYTE) malloc(cbEncodedCertReqSize);
			if (!pbSignedEncodedCertReq) 
			{
				dwError = GetLastError();
				__leave;
			}
			if(!CryptSignAndEncodeCertificate(
				  hCryptProvRootCertificate,                     // Crypto provider
				  AT_SIGNATURE,                 // Key spec
				  X509_ASN_ENCODING,               // Encoding type
				  X509_CERT_TO_BE_SIGNED, // Struct type
				  &CertInfo,                   // Struct info        
				  &SigAlg,                        // Signature algorithm
				  NULL,                           // Not used
				  pbSignedEncodedCertReq,         // Pointer
				  &cbEncodedCertReqSize))         // Length of the message
			{
				dwError = GetLastError();
				__leave;
			}
			// create context
			//////////////////
			pNewCertificateContext = CertCreateCertificateContext(X509_ASN_ENCODING,pbSignedEncodedCertReq,cbEncodedCertReqSize);
			if (!pNewCertificateContext)
			{
				dwError = GetLastError();
				__leave;
			}
		}

		// save context property to access the private key later
		// except for smart card (because certificate is associated to the key
		// (container name doesn't contain the real container name but \\.\ReaderName)
		//////////////////////////////////////////////////////
		if (pCertificateInfo->dwSaveon != UI_CERTIFICATE_INFO_SAVEON_SMARTCARD)
		{
			memset(&KeyProvInfo,0, sizeof(KeyProvInfo));
			KeyProvInfo.pwszProvName = szProviderName;
			KeyProvInfo.pwszContainerName = szContainerName;
			KeyProvInfo.dwProvType = PROV_RSA_FULL;
			KeyProvInfo.dwKeySpec = pCertificateInfo->dwKeyType;
			if (pCertificateInfo->dwSaveon == UI_CERTIFICATE_INFO_SAVEON_SYSTEMSTORE)
			{
				KeyProvInfo.dwFlags = CRYPT_MACHINE_KEYSET;
			}

			CertSetCertificateContextProperty(pNewCertificateContext,CERT_KEY_PROV_INFO_PROP_ID,0,&KeyProvInfo);
		}

		// save the certificate
		///////////////////////
		switch (pCertificateInfo->dwSaveon)
		{
		case UI_CERTIFICATE_INFO_SAVEON_USERSTORE: // user store
			hCertStore = CertOpenStore(CERT_STORE_PROV_SYSTEM,0,NULL,CERT_SYSTEM_STORE_CURRENT_USER,_T("My"));
			if (!hCertStore)
			{
				dwError = GetLastError();
				__leave;
			}
			if (CertAddCertificateContextToStore(hCertStore,pNewCertificateContext,CERT_STORE_ADD_ALWAYS,NULL))
			{
				//CryptUIDlgViewContext(CERT_STORE_CERTIFICATE_CONTEXT,pNewCertificateContext,NULL,NULL,0,NULL);
			}
			else
			{
				dwError = GetLastError();
				__leave;
			}
			break;
		case UI_CERTIFICATE_INFO_SAVEON_SYSTEMSTORE: // machine store
			// set security -> admin and system
			// create SYSTEM SID

			if (!AllocateAndInitializeSid(&sia, 1, SECURITY_LOCAL_SYSTEM_RID,0, 0, 0, 0, 0, 0, 0, &pSidSystem))
			{
				dwError = GetLastError();
				__leave;
			}

			// create Local Administrators alias SID
			if (!AllocateAndInitializeSid(&sia, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0,0, 0, &pSidAdmins))
			{
				dwError = GetLastError();
				__leave;
			}
			EXPLICIT_ACCESS ea[2];
			ZeroMemory(&ea, sizeof(ea));
			// fill an entry for the SYSTEM account
			ea[0].grfAccessMode = GRANT_ACCESS;
			ea[0].grfAccessPermissions = GENERIC_ALL;
			ea[0].grfInheritance = NO_INHERITANCE;
			ea[0].Trustee.MultipleTrusteeOperation = NO_MULTIPLE_TRUSTEE;
			ea[0].Trustee.pMultipleTrustee = NULL;
			ea[0].Trustee.TrusteeForm = TRUSTEE_IS_SID;
			ea[0].Trustee.TrusteeType = TRUSTEE_IS_WELL_KNOWN_GROUP;
			ea[0].Trustee.ptstrName = (LPTSTR)pSidSystem;
			// fill an entry for the Administrators alias
			ea[1].grfAccessMode = GRANT_ACCESS;
			ea[1].grfAccessPermissions = GENERIC_ALL;
			ea[1].grfInheritance = NO_INHERITANCE;
			ea[1].Trustee.MultipleTrusteeOperation = NO_MULTIPLE_TRUSTEE;
			ea[1].Trustee.pMultipleTrustee = NULL;
			ea[1].Trustee.TrusteeForm = TRUSTEE_IS_SID;
			ea[1].Trustee.TrusteeType = TRUSTEE_IS_ALIAS;
			ea[1].Trustee.ptstrName = (LPTSTR)pSidAdmins;
			// create a DACL
			dwError = SetEntriesInAcl(2, ea, NULL, &pDacl);
			if (dwError != ERROR_SUCCESS)
				__leave;
			pSD = (PSECURITY_DESCRIPTOR) malloc(SECURITY_DESCRIPTOR_MIN_LENGTH);
			if (!pSD)
			{
				__leave;
			}
			if (!InitializeSecurityDescriptor(pSD, SECURITY_DESCRIPTOR_REVISION))
			{
				dwError = GetLastError();
				__leave;
			}
			// Add the ACL to the security descriptor.
			if (!SetSecurityDescriptorDacl(pSD,TRUE,pDacl,FALSE))
			{
				dwError = GetLastError();
				__leave;
			}
			if (!SetSecurityDescriptorOwner(pSD,pSidAdmins,FALSE))
			{
				dwError = GetLastError();
				__leave;
			}
			if (!SetSecurityDescriptorGroup (pSD,pSidAdmins,FALSE))
			{
				dwError = GetLastError();
				__leave;
			}
			if(!CryptSetProvParam(hCryptProvNewCertificate,PP_KEYSET_SEC_DESCR,(BYTE*)pSD,DACL_SECURITY_INFORMATION))
			{
				dwError = GetLastError();
				__leave;
			}
			

			hCertStore = CertOpenStore(CERT_STORE_PROV_SYSTEM,0,NULL,CERT_SYSTEM_STORE_LOCAL_MACHINE,_T("Root"));
			if (!hCertStore)
			{
				dwError = GetLastError();
				__leave;
			}
			if (CertAddCertificateContextToStore(hCertStore,pNewCertificateContext,CERT_STORE_ADD_ALWAYS,NULL))
			{
				//CryptUIDlgViewContext(CERT_STORE_CERTIFICATE_CONTEXT,pNewCertificateContext,NULL,NULL,0,NULL);
			}
			else
			{
				dwError = GetLastError();
				__leave;
			}
			break;		
		case UI_CERTIFICATE_INFO_SAVEON_FILE: // file
			
			WizInfo.dwSize = sizeof(CRYPTUI_WIZ_EXPORT_INFO);
			WizInfo.dwSubjectChoice=CRYPTUI_WIZ_EXPORT_CERT_CONTEXT;
			WizInfo.pCertContext=pNewCertificateContext;

			// don't care about return value
//			CryptUIWizExport(0,hMainWnd,_T("Export"),&WizInfo,NULL);
			
			break;
		case UI_CERTIFICATE_INFO_SAVEON_SMARTCARD: // smart card
			if (!CryptSetKeyParam(hKey, KP_CERTIFICATE,pNewCertificateContext->pbCertEncoded, 0))
			{
				dwError = GetLastError();
				__leave;
			}
			break;
		}
		if (pCertificateInfo->fReturnCerticateContext)
		{
			pCertificateInfo->pNewCertificate = CertDuplicateCertificateContext(pNewCertificateContext);
		}
		// don't destroy the container is creation is successfull
		if (pCertificateInfo->dwSaveon != UI_CERTIFICATE_INFO_SAVEON_FILE) 
			bDestroyContainer = FALSE;
		fReturn = TRUE;
	}
	__finally
	{
		if (pNewCertificateContext) CertFreeCertificateContext(pNewCertificateContext);
		if (CertInfo.rgExtension) free(CertInfo.rgExtension);
		if (pbKeyUsage) free(pbKeyUsage);
		if (pbBasicConstraints) free(pbBasicConstraints);
		if (pbEnhKeyUsage) free(pbEnhKeyUsage);
		if (CertEnhKeyUsage.rgpszUsageIdentifier) free(CertEnhKeyUsage.rgpszUsageIdentifier);
		if (hKey) CryptDestroyKey(hKey);
		if (SubjectIssuerBlob.pbData) free(SubjectIssuerBlob.pbData);
		if (hCertStore) CertCloseStore(hCertStore,0);
		if (pbSignedEncodedCertReq) free(pbSignedEncodedCertReq);
		if (pbPublicKeyInfo) free(pbPublicKeyInfo);
		if (hCryptProvNewCertificate) CryptReleaseContext(hCryptProvNewCertificate,0);
		if (hCryptProvRootCertificate) CryptReleaseContext(hCryptProvRootCertificate,0);
		if (bDestroyContainer)
		{
			// if a temp container has been created, delete it
			CryptAcquireContext(
				&hCryptProvNewCertificate,
				szContainerName,          
				szProviderName,           
				PROV_RSA_FULL,      
				CRYPT_DELETE_KEYSET);
		}
		
		if (szContainerName) 
		{
			if (pCertificateInfo->dwSaveon == 3)
				LocalFree(szContainerName);
			else
				RpcStringFree((RPC_WSTR*)&szContainerName);
		}
		if (pSidSystem)
			FreeSid(pSidSystem);
		if (pSidAdmins)
			FreeSid(pSidAdmins);
		if (pDacl)
			LocalFree((HLOCAL)pDacl);
		if (pSD)
			free(pSD);
	}
	SetLastError(dwError);
	return fReturn;
}

BOOL ClearCard(PTSTR szReaderName, PTSTR szCardName)
{
	//delete
	BOOL bStatus = FALSE;
	WCHAR szProviderName[1024];
	DWORD dwProviderNameLen = 1024;
	CHAR szContainerName[1024];
	DWORD dwContainerNameLen = 1024;
	DWORD dwFlags;
	HCRYPTPROV HMainCryptProv,hProv;
	DWORD dwError = 0;
	if (!SchGetProviderNameFromCardName(szCardName, szProviderName, &dwProviderNameLen))
	{
		return FALSE;
	}

	size_t ulNameLen = _tcslen(szReaderName);
	LPTSTR szMainContainerName = (LPTSTR) malloc((ulNameLen + 6) * sizeof(TCHAR));
	if (!szMainContainerName)
	{
		return FALSE;
	}
	_stprintf_s(szMainContainerName,(ulNameLen + 6), _T("\\\\.\\%s\\"), szReaderName);

	bStatus = CryptAcquireContext(&HMainCryptProv,
				szMainContainerName,
				szProviderName,
				PROV_RSA_FULL,
				0);
	if (!bStatus)
	{
		free(szMainContainerName);
		return FALSE;
	}
	dwFlags = CRYPT_FIRST;
	/* Enumerate all the containers */
	while (CryptGetProvParam(HMainCryptProv,
				PP_ENUMCONTAINERS,
				(LPBYTE) szContainerName,
				&dwContainerNameLen,
				dwFlags)
			)
	{
		// convert the container name to unicode
		int wLen = MultiByteToWideChar(CP_ACP, 0, szContainerName, -1, NULL, 0);
		LPWSTR szWideContainerName = (LPWSTR) LocalAlloc(0, wLen * sizeof(WCHAR));
		MultiByteToWideChar(CP_ACP, 0, szContainerName, -1, szWideContainerName, wLen);

		// Acquire a context on the current container
		if (CryptAcquireContext(&hProv,
				szWideContainerName,
				szProviderName,
				PROV_RSA_FULL,
				CRYPT_DELETEKEYSET))
		{
			dwError = GetLastError();
		}
		dwFlags = CRYPT_NEXT;
		dwContainerNameLen = 1024;
	}
	CryptReleaseContext(HMainCryptProv,0);
	free(szMainContainerName);
	SetLastError(dwError);
	return TRUE;
}

BOOL ImportFileToSmartCard(PTSTR szFileName, PTSTR szPassword, PTSTR szReaderName, PTSTR szCardname)
{
	BOOL fReturn = FALSE;
	CRYPT_DATA_BLOB DataBlob = {0};
	HANDLE hFile = INVALID_HANDLE_VALUE;
	HCERTSTORE hCS = NULL;
	DWORD dwRead = 0;
	TCHAR szProviderName[1024];
	DWORD dwProviderNameLen = ARRAYSIZE(szProviderName);
	PWSTR szContainerName = NULL;
	HCRYPTPROV hCardProv = NULL, hProv = NULL;
	PCCERT_CONTEXT pCertContext = NULL;
	BOOL fFreeProv;
	DWORD dwKeySpec;
	HCRYPTKEY hKey = NULL, hSessionKey = NULL, hCardKey = NULL;
	PBYTE pbData = NULL;
	DWORD dwSize = 0;
	DWORD dwError = 0;
	__try
	{
		hFile = CreateFile(szFileName,GENERIC_READ,FILE_SHARE_READ,NULL,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,NULL);
		if (hFile == INVALID_HANDLE_VALUE)
		{
			dwError = GetLastError();
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"CreateFile 0x%08x",dwError);
			__leave;
		}
		DataBlob.cbData = GetFileSize(hFile,NULL);
		if (!DataBlob.cbData)
		{
			dwError = GetLastError();
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"GetFileSize 0x%08x",dwError);
			__leave;
		}
		DataBlob.pbData = (PBYTE) malloc(DataBlob.cbData);
		if (!DataBlob.pbData)
		{
			dwError = GetLastError();
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"malloc 0x%08x",dwError);
			__leave;
		}
		if (!ReadFile(hFile, DataBlob.pbData, DataBlob.cbData, &dwRead, NULL))
		{
			dwError = GetLastError();
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"ReadFile 0x%08x",dwError);
			__leave;
		}
		hCS = PFXImportCertStore(&DataBlob, szPassword, CRYPT_EXPORTABLE | CRYPT_USER_KEYSET );
		if(!hCS)
		{
			dwError = GetLastError();
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"PFXImportCertStore 0x%08x",dwError);
			__leave;
		}
		// provider name
		if (!SchGetProviderNameFromCardName(szCardname, szProviderName, &dwProviderNameLen))
		{
			dwError = GetLastError();
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"SchGetProviderNameFromCardName 0x%08x",dwError);
			__leave;
		}
		// container name from card name
		szContainerName = (LPTSTR) malloc((_tcslen(szReaderName) + 6) * sizeof(TCHAR));
		if (!szContainerName)
		{
			//dwError = GetLastError();
			dwError = GetLastError();
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"malloc 0x%08x",dwError);
			__leave;
		}
		_stprintf_s(szContainerName,(_tcslen(szReaderName) + 6), _T("\\\\.\\%s\\"), szReaderName);
		pCertContext = CertEnumCertificatesInStore(hCS, NULL);
		while( pCertContext )
		{
			if (CertGetCertificateContextProperty(pCertContext,CERT_KEY_PROV_INFO_PROP_ID, pbData, &dwSize))
			{
				
				if (! CryptAcquireCertificatePrivateKey(pCertContext, CRYPT_ACQUIRE_SILENT_FLAG, NULL, &hProv, &dwKeySpec, &fFreeProv))
				{
					dwError = GetLastError();
					EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"CryptAcquireCertificatePrivateKey 0x%08x",dwError);
					__leave;
				}
				if (!CryptGetUserKey(hProv, dwKeySpec, &hKey))
				{
					dwError = GetLastError();
					EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"CryptGetUserKey 0x%08x",dwError);
					__leave;
				}
				if (!CryptGenKey(hProv, CALG_3DES, CRYPT_EXPORTABLE,&hSessionKey))
				{
					dwError = GetLastError();
					EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"CryptGenKey 0x%08x",dwError);
					__leave;
				}
				if (!CryptExportKey(hKey, hSessionKey, PRIVATEKEYBLOB, 0, NULL, &dwSize))
				{
					dwError = GetLastError();
					EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"CryptExportKey 0x%08x",dwError);
					__leave;
				}
				pbData = (PBYTE) malloc(dwSize);
				if (!pbData)
				{
					dwError = GetLastError();
					EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"malloc 0x%08x",dwError);
					__leave;
				}
				if (!CryptExportKey(hKey, hSessionKey, PRIVATEKEYBLOB, 0, pbData, &dwSize))
				{
					dwError = GetLastError();
					EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"CryptExportKey 0x%08x",dwError);
					__leave;
				}
				if (! CryptAcquireContext(&hCardProv,szContainerName, szProviderName, PROV_RSA_FULL,CRYPT_NEWKEYSET))
				{
					dwError = GetLastError();
					EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"CryptAcquireContext 0x%08x",dwError);
					__leave;
				}
				if (!CryptImportKey(hCardProv, pbData, dwSize, hSessionKey, 0, &hCardKey))
				{
					dwError = GetLastError();
					EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"CryptImportKey 0x%08x",dwError);
					__leave;
				}
				if (!CryptSetKeyParam(hCardKey, KP_CERTIFICATE, pbData, 0))
				{
					dwError = GetLastError();
					EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"CryptSetKeyParam 0x%08x",dwError);
					__leave;
				}
				EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"OK");
				__leave;
			}
			pCertContext = CertEnumCertificatesInStore(hCS, pCertContext);
		}
		EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"not found");
	}
	__finally
	{
		if (hCardKey)
			CryptDestroyKey(hCardKey);
		if (pbData)
			free(pbData);
		if (hSessionKey)
			CryptDestroyKey(hSessionKey);
		if (hKey)
			CryptDestroyKey(hKey);
		if (hProv)
			CryptReleaseContext(hProv, 0);
		if (pCertContext)
			CertFreeCertificateContext(pCertContext);
		if (hCardProv)
			CryptReleaseContext(hCardProv, 0);
		if (szContainerName) 
			free(szContainerName);			
		if (hCS)
			CertCloseStore(hCS, 0);
		if (DataBlob.pbData)
			free(DataBlob.pbData);
		if (hFile != INVALID_HANDLE_VALUE)
			CloseHandle(hFile);
	}
	SetLastError(dwError);
	return fReturn;
}
