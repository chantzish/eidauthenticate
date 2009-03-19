#include <windows.h>
#include <tchar.h>

#include "../EIDCardLibrary/Tracing.h"
#include "../EIDCardLibrary/CContainer.h"
#include "../EIDCardLibrary/CContainerHolderFactory.h"
#include "../EIDCardLibrary/CertificateUtilities.h"
#include "../EIDCardLibrary/GPO.h"
#include "EIDTestUIUtil.h"

extern HWND hMainWnd;


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

void menu_CREDENTIAL_List()
{
	
	WCHAR szReader[256];
	WCHAR szCard[256];
	if (AskForCard(szReader,256,szCard,256))
	{
		CContainerHolderFactory<CContainerHolderTest> MyCredentialList;
		MyCredentialList.ConnectNotification(szReader,szCard,0);
		if (MyCredentialList.HasContainerHolder())
		{
			DWORD dwMax = MyCredentialList.ContainerHolderCount();
			for (DWORD dwI = 0; dwI < dwMax ; dwI++)
			{
				CContainerHolderTest* MyTest = MyCredentialList.GetContainerHolderAt(dwI);
				MessageBox(hMainWnd,MyTest->GetContainer()->GetUserNameW(),_T("test"),0);
			}
		}
		else
		{
			MessageBox(hMainWnd,_T("No Credential"),_T("test"),0);
		}
		MyCredentialList.DisconnectNotification(szReader);
	}
}

void menu_CRED_RP_Trigger()
{
	WCHAR szReader[256];
	WCHAR szCard[256];
	WCHAR szContainer[256];
	WCHAR szProvider[256];
	DWORD dwKeySpec = 0;
	PCCERT_CONTEXT pContext = NULL;
	SCARDCONTEXT hSCardContext = NULL;
	SCARD_READERSTATE rgscState = {0};

	if (AskForCard(szReader,256,szCard,256)) {
		rgscState.szReader = szReader;
		rgscState.dwCurrentState = SCARD_STATE_UNAWARE;
		if (SCARD_S_SUCCESS != SCardEstablishContext(SCARD_SCOPE_USER,NULL,NULL,&hSCardContext))
		{
			return;
		}
		if (SCARD_S_SUCCESS != SCardGetStatusChange(hSCardContext, (DWORD) 0 ,&rgscState,1))
		{
			SCardReleaseContext(hSCardContext);
			return;
		}
		SCardReleaseContext(hSCardContext);
		if (pContext = SelectCerts(szReader,szCard,szProvider, 256, szContainer,256, &dwKeySpec)) 
		{

			CContainer* container = new CContainer(szReader, szCard, szProvider, szContainer, dwKeySpec, (rgscState.dwEventState)>>16,pContext);
			if (container->TriggerRemovePolicy())
			{
				MessageBox(hMainWnd,_T("Success"),_T("Success"),0);
			}
			else
			{
				MessageBox(hMainWnd,_T("Failure"),_T("Failure"),0);
			}
		}
		CertFreeCertificateContext(pContext);
	}
}