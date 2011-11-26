class CContainerHolderTest
{
public:
	CContainerHolderTest(CContainer* pContainer);

	virtual ~CContainerHolderTest();
	void Release();

	HRESULT SetUsageScenario(__in CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus,__in DWORD dwFlags){return S_OK;}
	CContainer* GetContainer();

private:
	CContainer* _pContainer;
};
