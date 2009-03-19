#pragma once
#include <iostream>
#include <list>
#include "../EIDCardLibrary/EIDCardLibrary.h"

class CContainer 
{

  public:
    CContainer(__in LPCTSTR szReaderName, __in LPCTSTR szCardName, __in LPCTSTR szProviderName, 
		__in LPCTSTR szContainerName, __in DWORD KeySpec, __in USHORT ActivityCount, __in PCCERT_CONTEXT pCertContext);

    virtual ~CContainer();

	PTSTR GetUserName();
	PTSTR GetProviderName();
	PTSTR GetContainerName();
	DWORD GetKeySpec();

	PCCERT_CONTEXT GetContainer();
	BOOL IsOnReader(__in LPCTSTR szReaderName);
	
	PEID_SMARTCARD_CSP_INFO GetCSPInfo();
	void FreeCSPInfo(PEID_SMARTCARD_CSP_INFO);

	BOOL Erase();
	BOOL ViewCertificate(HWND hWnd = NULL);

	BOOL TriggerRemovePolicy();
	
  private:

	LPTSTR					_szReaderName;
	LPTSTR					_szCardName;
	LPTSTR					_szProviderName;
	LPTSTR					_szContainerName;
	LPTSTR					_szUserName;
	DWORD					_KeySpec;
	USHORT					_ActivityCount;
	PCCERT_CONTEXT			_pCertContext;
};
