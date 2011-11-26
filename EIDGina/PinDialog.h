// LogonDialog.h
//
// Gather user credentials for Logon.
//

#pragma once

#include "WinLogonInterface.h"
#include "GinaModalDialog.h"
#include "GinaSmartCardCredential.h"
#include "resource.h"

class PinDialog : public GinaModalDialog {
public:
    PinDialog(IWinLogon* pWinLogon, CContainerHolderFactory<GinaSmartCardCredential> *pCredentialList)
        : GinaModalDialog(pWinLogon, IDD_LOGONPIN), pin(0) 
	{
		_pCredentialList = pCredentialList;
    }
    ~PinDialog() {
        if (pin)   delete pin;
    }
    
    INT_PTR DialogProc(UINT msg, WPARAM wp, LPARAM lp);
	GinaSmartCardCredential* certificate;
	CContainerHolderFactory<GinaSmartCardCredential> *_pCredentialList;
    wchar_t* pin;
};
