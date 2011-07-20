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
    PinDialog(IWinLogon* pWinLogon)
        : GinaModalDialog(pWinLogon, IDD_LOGONPIN), pin(0) {
    }
    ~PinDialog() {
        if (pin)   delete pin;
    }
    
    INT_PTR DialogProc(UINT msg, WPARAM wp, LPARAM lp);
	GinaSmartCardCredential* certificate;
    wchar_t* pin;
};
