#pragma once

#include <Windows.h>
#include <tchar.h>
#include "global.h"
#include "CWinlogon.h"
#include "resource.h"
#include <credentialprovider.h>
#include "../EIDCardLibrary/CContainer.h"
#include "GinaSmartCardCredential.h"
#include "../EIDCardLibrary/GPO.h"
#include "../EIDCardLibrary/CContainerHolderFactory.h"

class PINDialog {
public:
    PINDialog(CWinLogon* pWinLogon);
	~PINDialog();
    int Show();
	BOOL Populate();
    virtual INT_PTR DialogProc(UINT msg, WPARAM wp, LPARAM lp);
	WCHAR szPin[255];
	GinaSmartCardCredential* pCredential;
protected:
	PINDialog();
	CWinLogon* _pWinLogon;
    static INT_PTR CALLBACK _dialogProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp);
    HWND       _hwnd;
	CContainerHolderFactory<GinaSmartCardCredential> _pCredentialList;
	static void PINDialog::CenterWindow(HWND hwnd);
	WCHAR _szReader[255];
	WCHAR _szCard[255];
};
