// NoticeDialog.h
//
// Dialog displayed for either SAS notice or wksta locked notice
//

#pragma once

#include "WinLogonInterface.h"
#include "GinaModalDialog.h"
#include "resource.h"

class NoticeDialog : public GinaModalDialog {
public:
    NoticeDialog(IWinLogon* pWinLogon, int dialogResourceID)
        : GinaModalDialog(pWinLogon, dialogResourceID) {
		bkBkgBrush = CreateSolidBrush(RGB(255,255,255));
    }

	~NoticeDialog()
	{
		if(bkBkgBrush != NULL)
		{
			DeleteObject (bkBkgBrush);
		}
	}

	INT_PTR NoticeDialog::DialogProc(UINT msg, WPARAM wp, LPARAM lp) {
		switch (msg) 
		{
		case WM_CTLCOLORDLG:
			return (INT_PTR) bkBkgBrush;
		}
		return FALSE;
	}
	
	HBRUSH bkBkgBrush;
};
