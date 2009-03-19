#pragma once
#include <iostream>
#include <list>
#include <credentialprovider.h>
#include "EIDCardLibrary.h"

class ISmartCardConnectionNotifierRef
{
	public:
	virtual ~ISmartCardConnectionNotifierRef() {}
	virtual void Callback(EID_CREDENTIAL_PROVIDER_READER_STATE Message,__in LPCTSTR Reader,__in_opt LPCTSTR CardName, __in_opt USHORT ActivityCount) 
	{
		UNREFERENCED_PARAMETER(Message);
		UNREFERENCED_PARAMETER(Reader);
		UNREFERENCED_PARAMETER(CardName);
		UNREFERENCED_PARAMETER(ActivityCount);
	
	};
};

class CSmartCardConnectionNotifier 
{

  public:
    CSmartCardConnectionNotifier() ;
	CSmartCardConnectionNotifier(ISmartCardConnectionNotifierRef*);

    virtual ~CSmartCardConnectionNotifier();
	
	HRESULT Start();
	HRESULT Stop();
  private:

	BOOL ValidateCard(SCARD_READERSTATE rgscState);
	LONG GetReaderStates(SCARD_READERSTATE rgscState[MAXIMUM_SMARTCARD_READERS],PDWORD dwRdrCount);
	LONG WaitForSmartCardInsertion();
	static DWORD WINAPI _ThreadProc(LPVOID lpParameter);
	
	void Callback(EID_CREDENTIAL_PROVIDER_READER_STATE Message,__in LPCTSTR Reader,__in_opt LPCTSTR CardName, __in_opt USHORT ActivityCount);

	HANDLE                  _hThread;
	HANDLE					_hAccessStartedEvent;
	SCARDCONTEXT			_hSCardContext;
	ISmartCardConnectionNotifierRef*			 _CallBack;
};
