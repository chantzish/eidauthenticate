#include <windows.h>
#include <tchar.h>

#include "../EIDCardLibrary/Tracing.h"
#include "../EIDCardLibrary/GPO.h"
#include "../EIDCardLibrary/CContainer.h"
#include "../EIDCardLibrary/CContainerHolderFactory.h"
#include "../EIDCardLibrary/StoredCredentialManagement.h"

#include "Checks.h"

#pragma comment(lib,"Netapi32")
#pragma comment(lib,"Winscard")
#pragma comment(lib,"Scarddlg")

PTSTR szAction = TEXT("Solve");

#define EnableAction(INDEX) rgCheckInfo[INDEX].szAction = szAction;

CHECKINFO rgCheckInfo[ ] = 
{
    {TEXT("Card contains certificate"), NULL, CHECK_FAILED, NULL},
	{TEXT("Certificate match username"), NULL, CHECK_FAILED, NULL},
    {TEXT("Certificate Validation"), NULL, CHECK_FAILED, NULL},
	{TEXT("Crypto"), NULL, CHECK_FAILED, NULL},
	{TEXT("Account a has password"), NULL, CHECK_FAILED, NULL},
	{TEXT("Remove Policy"), NULL, CHECK_FAILED, NULL},
	{TEXT("Require Smart Card Logon Policy"), NULL, CHECK_FAILED, NULL},
};

DWORD dwCheckInfoNum = ARRAYSIZE(rgCheckInfo);

class CContainerHolderTest
{
public:
	CContainerHolderTest(CContainer* pContainer)
	{
		_pContainer = pContainer;
	}

	virtual ~CContainerHolderTest()
	{
		if (_pContainer)
		{
			delete _pContainer;
		}
	}
	void Release()
	{
		delete this;
	}
	HRESULT SetUsageScenario(__in CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus,__in DWORD dwFlags){return S_OK;}
	CContainer* GetContainer()
	{
		return _pContainer;
	}
private:
	CContainer* _pContainer;
};

BOOL HasEmptyPasswordAccount(PTSTR pszUserName)
{
	/*BOOL fReturn = FALSE;
	PUSER_INFO_1 pUserInfo;
	if (NERR_Success == NetUserGetInfo(NULL, pszUserName, 1, (PBYTE*) &pUserInfo))
	{
		fReturn = (pUserInfo->usri1_flags & UF_PASSWD_NOTREQD ) ? TRUE: FALSE;
		NetApiBufferFree(pUserInfo);
	}
	return fReturn;*/
	
	HANDLE hToken = NULL; 
	BOOL bLoggedOn = LogonUser(pszUserName, TEXT(""), NULL, LOGON32_LOGON_INTERACTIVE, LOGON32_PROVIDER_DEFAULT, &hToken);
	DWORD dwError = GetLastError();

	if(bLoggedOn)
	{
		return TRUE;
		CloseHandle(hToken);
	}
	if (dwError == 1327)
	{
		return TRUE;
	}
	return FALSE;
}

void CheckRemovePolicy()
{
	HKEY key;
	
	TCHAR szValue[2]=TEXT("0");
	DWORD size = sizeof(szValue);
	DWORD type=REG_SZ;	
	DWORD dwValue = 0;
	if (RegOpenKeyEx(HKEY_LOCAL_MACHINE,
		TEXT("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon"),
		NULL, KEY_READ, &key)==ERROR_SUCCESS){
		if (RegQueryValueEx(key,TEXT("scremoveoption"),NULL, &type,(LPBYTE) szValue, &size)==ERROR_SUCCESS)
		{
			dwValue = _tstoi(szValue);
		}
		RegCloseKey(key);
	}
	// remove policy active
	if (dwValue)
	{
		if (RegOpenKeyEx(HKEY_LOCAL_MACHINE,
			TEXT("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Removal Policy"),
			NULL, KEY_READ, &key)==ERROR_SUCCESS){
				rgCheckInfo[CHECK_REMOVEPOLICY].szComment = (PTSTR) malloc(sizeof(TCHAR)*100);
				_stprintf_s(rgCheckInfo[CHECK_REMOVEPOLICY].szComment, 100, TEXT("Enabled"));
				rgCheckInfo[CHECK_REMOVEPOLICY].dwStatus = CHECK_INFO;
		}
		else
		{
			rgCheckInfo[CHECK_REMOVEPOLICY].szComment = (PTSTR) malloc(sizeof(TCHAR)*100);
			_stprintf_s(rgCheckInfo[CHECK_REMOVEPOLICY].szComment, 100, TEXT("Enabled but the service is not running"));
			rgCheckInfo[CHECK_REMOVEPOLICY].dwStatus = CHECK_WARNING;
		}
	}
	// not active
	else
	{
		rgCheckInfo[CHECK_REMOVEPOLICY].szComment = (PTSTR) malloc(sizeof(TCHAR)*100);
		_stprintf_s(rgCheckInfo[CHECK_REMOVEPOLICY].szComment, 100, TEXT("Disabled"));
		rgCheckInfo[CHECK_REMOVEPOLICY].dwStatus = CHECK_INFO;
	}
}

BOOL DoChecks()
{
	DWORD dwTrustError = 0;
	TCHAR szReader[1024];
	TCHAR szCard[1024];
	DWORD			dwBestId;
	DWORD			dwLevel;
	TCHAR szUserName[1024];
	DWORD dwSize = ARRAYSIZE(szUserName);

	for (DWORD dwI = 0; dwI < dwCheckInfoNum; dwI++)
	{
		rgCheckInfo[dwI].dwStatus = CHECK_FAILED;
		if (rgCheckInfo[dwI].szComment)
		{
			free(rgCheckInfo[dwI].szComment);
			rgCheckInfo[dwI].szComment = NULL;
		}
		rgCheckInfo[dwI].szAction = NULL;
		if (rgCheckInfo[dwI].pCustomInfo)
		{
			free(rgCheckInfo[dwI].pCustomInfo);
			rgCheckInfo[dwI].pCustomInfo = NULL;
		}
	}

	GetUserName(szUserName, &dwSize);

	if (!AskForCard(szReader, ARRAYSIZE(szReader), szCard, ARRAYSIZE(szCard)))
	{
		return FALSE;
	}
	dwLevel = 0;
	dwBestId = 0;
	CContainerHolderFactory<CContainerHolderTest> MyCredentialList;
	MyCredentialList.ConnectNotification(szReader,szCard,0);
	if (MyCredentialList.HasContainerHolder())
	{
		rgCheckInfo[CHECK_CONTAINSCERT].dwStatus = CHECK_SUCCESS;
		DWORD dwMax = MyCredentialList.ContainerHolderCount();
		rgCheckInfo[CHECK_CONTAINSCERT].szComment = (PTSTR) malloc(sizeof(TCHAR)*100);
		_stprintf_s(rgCheckInfo[CHECK_CONTAINSCERT].szComment, 100, TEXT("Contains %d Certificate(s)"),dwMax);
		for (DWORD dwI = 0; dwI < dwMax ; dwI++)
		{
			CContainerHolderTest* MyTest = MyCredentialList.GetContainerHolderAt(dwI);
			if (_tcscmp(MyTest->GetContainer()->GetUserName(),szUserName)==0)
			{
				if (dwLevel == 0) 
				{
					dwLevel = 1;
					dwBestId = dwI;
				}
				CContainer* container = MyTest->GetContainer();
				PCCERT_CONTEXT pCertContext = container->GetContainer();
				if (IsTrustedCertificate(pCertContext))
				{
					if (dwLevel == 1) 
					{
						dwLevel = 2;
						dwBestId = dwI;
					}
					if (CanEncryptPassword(NULL,0, pCertContext))
					{
						if (dwLevel == 2) 
						{
							dwLevel = 3;
							dwBestId = dwI;
							rgCheckInfo[CHECK_CRYPTO].dwStatus = CHECK_SUCCESS;
							rgCheckInfo[CHECK_CRYPTO].szComment = (PTSTR) malloc(sizeof(TCHAR)*100);
							_stprintf_s(rgCheckInfo[CHECK_CRYPTO].szComment, 100, TEXT("Card supports encryption"));
						}
					}					
				}
				CertFreeCertificateContext(pCertContext);
			}
		}
	}
	else
	{
		rgCheckInfo[CHECK_CONTAINSCERT].szComment = (PTSTR) malloc(sizeof(TCHAR)*100);
		_stprintf_s(rgCheckInfo[CHECK_CONTAINSCERT].szComment, 100, TEXT("Contains %d Certificate(s)"),0);
	}
	// username
	if (MyCredentialList.HasContainerHolder())
	{
		CContainerHolderTest* MyTest = MyCredentialList.GetContainerHolderAt(dwBestId);
		if (dwLevel > 0)
		{
			rgCheckInfo[CHECK_USERNAME].dwStatus = CHECK_SUCCESS;
		}
		else
		{
			rgCheckInfo[CHECK_USERNAME].dwStatus = CHECK_FAILED;
			EnableAction(CHECK_USERNAME);
		}
		rgCheckInfo[CHECK_USERNAME].szComment = (PTSTR) malloc(sizeof(TCHAR)*200);
		_stprintf_s(rgCheckInfo[CHECK_USERNAME].szComment, 100, TEXT("Username(s) found : %s"),
						MyCredentialList.GetContainerHolderAt(0)->GetContainer()->GetUserName());
		DWORD dwRemainingChar = (DWORD) (200 - _tcsclen(rgCheckInfo[CHECK_USERNAME].szComment) - 1);
		DWORD dwMax = MyCredentialList.ContainerHolderCount();
		for (DWORD dwI = 1; dwI < dwMax; dwI++)
		{
			_tcscat_s(rgCheckInfo[CHECK_USERNAME].szComment,dwRemainingChar,TEXT(", "));
			dwRemainingChar = (DWORD) (200 - _tcsclen(rgCheckInfo[CHECK_USERNAME].szComment) - 1);
			_tcscat_s(rgCheckInfo[CHECK_USERNAME].szComment,dwRemainingChar,MyCredentialList.GetContainerHolderAt(dwI)->GetContainer()->GetUserName());
			dwRemainingChar = (DWORD) (200 - _tcsclen(rgCheckInfo[CHECK_USERNAME].szComment) - 1);
		}
		rgCheckInfo[CHECK_USERNAME].pCustomInfo = malloc(sizeof(TCHAR)*100);
		_stprintf_s((PTSTR) rgCheckInfo[CHECK_USERNAME].pCustomInfo, 100, TEXT("%s"),
						MyTest->GetContainer()->GetUserName());
	}
	// certificate validation
	if (dwLevel < 1)
	{			
		if (MyCredentialList.HasContainerHolder())
		{
			CContainerHolderTest* MyTest = MyCredentialList.GetContainerHolderAt(dwBestId);
			PCCERT_CONTEXT pCertContext = MyTest->GetContainer()->GetContainer();
			if (IsTrustedCertificate(pCertContext))
			{
				rgCheckInfo[CHECK_VALIDATION].dwStatus = CHECK_SUCCESS;
				rgCheckInfo[CHECK_VALIDATION].szComment = (PTSTR) malloc(sizeof(TCHAR)*100);
				_stprintf_s(rgCheckInfo[CHECK_VALIDATION].szComment, 100, TEXT("Success"));
			}
			else
			{
				rgCheckInfo[CHECK_VALIDATION].dwStatus = CHECK_FAILED;
				rgCheckInfo[CHECK_VALIDATION].szComment = (PTSTR) malloc(sizeof(TCHAR)*100);
				_stprintf_s(rgCheckInfo[CHECK_VALIDATION].szComment, 100, TEXT("Failure (%s)"),GetTrustErrorText(GetLastError()));
				if (IsTrustedCertificate(pCertContext,EID_CERTIFICATE_FLAG_USERSTORE))
				{
					EnableAction(CHECK_VALIDATION);
				}
			}
		}
		else
		{
			rgCheckInfo[CHECK_VALIDATION].dwStatus = CHECK_FAILED;
			rgCheckInfo[CHECK_VALIDATION].szComment = (PTSTR) malloc(sizeof(TCHAR)*100);
			_stprintf_s(rgCheckInfo[CHECK_VALIDATION].szComment, 100, TEXT("Not tested"));
		}
	}
	if (dwLevel == 1)
	{
		CContainerHolderTest* MyTest = MyCredentialList.GetContainerHolderAt(dwBestId);
		PCCERT_CONTEXT pCertContext = MyTest->GetContainer()->GetContainer();
		rgCheckInfo[CHECK_VALIDATION].dwStatus = CHECK_FAILED;
		rgCheckInfo[CHECK_VALIDATION].szComment = (PTSTR) malloc(sizeof(TCHAR)*100);
		_stprintf_s(rgCheckInfo[CHECK_VALIDATION].szComment, 100, TEXT("Failure (%s)"),GetTrustErrorText(dwTrustError));
		if (IsTrustedCertificate(pCertContext,EID_CERTIFICATE_FLAG_USERSTORE))
		{
			EnableAction(CHECK_VALIDATION);
		}
	}
	if (dwLevel > 1)
	{
		rgCheckInfo[CHECK_VALIDATION].dwStatus = CHECK_SUCCESS;
		rgCheckInfo[CHECK_VALIDATION].szComment = (PTSTR) malloc(sizeof(TCHAR)*100);
		_stprintf_s(rgCheckInfo[CHECK_VALIDATION].szComment, 100, TEXT("Success"));
	}
	// encryption
	if (dwLevel == 2)
	{				
		rgCheckInfo[CHECK_CRYPTO].dwStatus = CHECK_WARNING;
		rgCheckInfo[CHECK_CRYPTO].szComment = (PTSTR) malloc(sizeof(TCHAR)*100);
		_stprintf_s(rgCheckInfo[CHECK_CRYPTO].szComment, 100, TEXT("Card does not support encryption"));
	}
	if (dwLevel < 2)
	{				
		if (MyCredentialList.HasContainerHolder())
		{
			CContainerHolderTest* MyTest = MyCredentialList.GetContainerHolderAt(dwBestId);
			PCCERT_CONTEXT pCertContext = MyTest->GetContainer()->GetContainer();
			if (CanEncryptPassword(NULL,0, pCertContext))
			{
				rgCheckInfo[CHECK_CRYPTO].dwStatus = CHECK_SUCCESS;
				rgCheckInfo[CHECK_CRYPTO].szComment = (PTSTR) malloc(sizeof(TCHAR)*100);
				_stprintf_s(rgCheckInfo[CHECK_CRYPTO].szComment, 100, TEXT("Card supports encryption"));
			}
			else
			{
				rgCheckInfo[CHECK_CRYPTO].dwStatus = CHECK_WARNING;
				rgCheckInfo[CHECK_CRYPTO].szComment = (PTSTR) malloc(sizeof(TCHAR)*100);
				_stprintf_s(rgCheckInfo[CHECK_CRYPTO].szComment, 100, TEXT("Card does not support encryption"));
			}
		}
		else
		{
			rgCheckInfo[CHECK_CRYPTO].dwStatus = CHECK_FAILED;
			rgCheckInfo[CHECK_CRYPTO].szComment = (PTSTR) malloc(sizeof(TCHAR)*100);
			_stprintf_s(rgCheckInfo[CHECK_CRYPTO].szComment, 100, TEXT("Not tested"));
		}
	}	
	// password
	if (HasEmptyPasswordAccount(szUserName))
	{
		rgCheckInfo[CHECK_HASPASSWORD].dwStatus = CHECK_WARNING;
		rgCheckInfo[CHECK_HASPASSWORD].szComment = (PTSTR) malloc(sizeof(TCHAR)*100);
		_stprintf_s(rgCheckInfo[CHECK_HASPASSWORD].szComment, 100, TEXT("Account doesn't have a password"));	
		rgCheckInfo[CHECK_HASPASSWORD].szAction = szAction;
	}
	else
	{
		rgCheckInfo[CHECK_HASPASSWORD].dwStatus = CHECK_SUCCESS;
		rgCheckInfo[CHECK_HASPASSWORD].szComment = (PTSTR) malloc(sizeof(TCHAR)*100);
		_stprintf_s(rgCheckInfo[CHECK_HASPASSWORD].szComment, 100, TEXT("Success"));						
	}
	CheckRemovePolicy();
	rgCheckInfo[CHECK_REQUIRESCLOGON].dwStatus = CHECK_INFO;
	if (GetPolicyValue(scforceoption))
	{
		rgCheckInfo[CHECK_REQUIRESCLOGON].szComment = (PTSTR) malloc(sizeof(TCHAR)*100);
		_stprintf_s(rgCheckInfo[CHECK_REQUIRESCLOGON].szComment, 100, TEXT("Enabled"));
	}
	else
	{
		rgCheckInfo[CHECK_REQUIRESCLOGON].szComment = (PTSTR) malloc(sizeof(TCHAR)*100);
		_stprintf_s(rgCheckInfo[CHECK_REQUIRESCLOGON].szComment, 100, TEXT("Disabled"));
	}
	return TRUE;
}
