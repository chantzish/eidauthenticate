
#include <credentialprovider.h>

class IContainerHolderList
{
	public:
	virtual ~IContainerHolderList() {}
	virtual CContainer* GetContainer() {return NULL;};
};

template <typename T> 

class CContainerHolderFactory
{
public:	
	CContainerHolderFactory();
	virtual ~CContainerHolderFactory();

	HRESULT SetUsageScenario(__in CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus,__in DWORD dwFlags);
	BOOL DisconnectNotification(__in LPCTSTR szReaderName);
	BOOL ConnectNotification(__in LPCTSTR szReaderName,__in LPCTSTR szCardName, __in USHORT ActivityCount);
	BOOL CreateItemFromCertificateBlob(__in LPCTSTR szReaderName,__in LPCTSTR szCardName,
															   __in LPCTSTR szProviderName, __in LPCTSTR szContainerName,
															   __in DWORD KeySpec, __in USHORT ActivityCount,
															   __in PBYTE Data, __in DWORD DataSize);
	BOOL HasContainerHolder();
	DWORD ContainerHolderCount();
	T* GetContainerHolderAt(DWORD dwIndex);
private:
	BOOL ConnectNotificationGeneric(__in LPCTSTR szReaderName,__in LPCTSTR szCardName, __in USHORT ActivityCount);
	BOOL ConnectNotificationBeid(__in LPCTSTR szReaderName,__in LPCTSTR szCardName, __in USHORT ActivityCount);
	BOOL CleanList();
	CREDENTIAL_PROVIDER_USAGE_SCENARIO _cpus;
    DWORD _dwFlags;
	std::list<T*> _CredentialList;
	
};



#include "CContainerHolderFactory.cpp"