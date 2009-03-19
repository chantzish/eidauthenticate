#include <windows.h>
#include <tchar.h>

#include "../EIDCardLibrary/Tracing.h"
#include "../EIDCardLibrary/GPO.h"
#include "../EIDCardLibrary/CContainer.h"
#include "../EIDCardLibrary/CContainerHolderFactory.h"
#include "../EIDCardLibrary/StoredCredentialManagement.h"
#include "../EIDCardLibrary/Package.h"

#include "global.h"
#include "EIDConfigurationWizard.h"


class CContainerHolderTest : public IContainerHolderList
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


BOOL WizardFinishButton(PTSTR szPassword)
{
	BOOL fReturn = FALSE;
	SCARDCONTEXT     hSC;
	OPENCARDNAME_EX  dlgStruct;
	LONG             lReturn;
	DWORD			dwBestId;
	DWORD			dwLevel;
	DWORD dwError = 0;
	TCHAR szReader[1024];
	TCHAR szCard[1024];

	TCHAR szUserName[1024];
	DWORD dwSize = ARRAYSIZE(szUserName);
	GetUserName(szUserName, &dwSize);

	lReturn = SCardEstablishContext(SCARD_SCOPE_USER,
									NULL,
									NULL,
									&hSC );
	if ( SCARD_S_SUCCESS != lReturn )
	{
		return FALSE;
	}

	// Initialize the structure.
	memset(&dlgStruct, 0, sizeof(dlgStruct));
	dlgStruct.dwStructSize = sizeof(dlgStruct);
	dlgStruct.hSCardContext = hSC;
	dlgStruct.dwFlags = SC_DLG_MINIMAL_UI;
	dlgStruct.lpstrRdr = szReader;
	dlgStruct.nMaxRdr = ARRAYSIZE(szReader);
	dlgStruct.lpstrCard = szCard;
	dlgStruct.nMaxCard = ARRAYSIZE(szCard);
	dlgStruct.lpstrTitle = L"Select Card";
	dlgStruct.dwShareMode = 0;
	// Display the select card dialog box.
	lReturn = SCardUIDlgSelectCard(&dlgStruct);
	SCardReleaseContext(hSC);
	if ( SCARD_S_SUCCESS != lReturn )
	{
		return FALSE;
	}
	
	dwLevel = 0;
	dwBestId = 0;
	CContainerHolderFactory<CContainerHolderTest> MyCredentialList;
	MyCredentialList.ConnectNotification(szReader,szCard,0);
	if (MyCredentialList.HasContainerHolder())
	{
		DWORD dwMax = MyCredentialList.ContainerHolderCount();
		for (DWORD dwI = 0; dwI < dwMax ; dwI++)
		{
			CContainerHolderTest* MyTest = MyCredentialList.GetContainerHolderAt(dwI);
			if (_tcscmp(MyTest->GetContainer()->GetUserName(),szUserName)==0)
			{
				CContainer* container = MyTest->GetContainer();
				PCCERT_CONTEXT pCertContext = container->GetContainer();
				if (IsTrustedCertificate(pCertContext,&dwError))
				{
					if (dwLevel == 0) 
					{
						dwLevel = 1;
						dwBestId = dwI;
					}
					if (CanEncryptPassword(NULL,0, pCertContext))
					{
						if (dwLevel == 1) 
						{
							dwLevel = 2;
							dwBestId = dwI;
						}
				
					}
				}
				CertFreeCertificateContext(pCertContext);
			}
		}
	}
	// container found
	if (dwLevel)
	{
		CContainerHolderTest* MyTest = MyCredentialList.GetContainerHolderAt(dwBestId);
		CContainer* container = MyTest->GetContainer();
		fReturn = LsaEIDCreateStoredCredential(szUserName, szPassword, container->GetProviderName(), container->GetContainerName(), container->GetKeySpec());
	}
	return fReturn;
}


BOOL CALLBACK	WndProc_05PASSWORD(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam)
{
	TCHAR szPassword[1024];
	switch(message)
	{
		case WM_NOTIFY :
        LPNMHDR pnmh = (LPNMHDR)lParam;
        switch(pnmh->code)
        {
			case PSN_SETACTIVE :
				//this is an interior page
				PropSheet_SetWizButtons(hWnd, PSWIZB_FINISH |	PSWIZB_BACK);
				break;
			case PSN_WIZFINISH :
				GetWindowText(GetDlgItem(hWnd,IDC_05PASSWORD),szPassword,ARRAYSIZE(szPassword));
				if (!WizardFinishButton(szPassword))
				{
					MessageBox(hWnd, TEXT("Error"), TEXT("Error"), MB_ICONERROR);
				}
				break;
		}
    }
	return FALSE;
}