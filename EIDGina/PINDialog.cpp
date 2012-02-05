// GinaModalDialog.cpp
//
// Gather user credentials for Modal.
//
#include <Windows.h>
#include <WinWlx.h>
#include "PINDialog.h"


PINDialog::PINDialog(CWinLogon* pWinLogon) : _pWinLogon(pWinLogon)
{
	pCredential = 0;
	_pCredentialList.SetUsageScenario(CPUS_LOGON,0);
	wcscpy_s(_szReader,ARRAYSIZE(_szReader), pWinLogon->_szReader);
	wcscpy_s(_szCard,ARRAYSIZE(_szCard), pWinLogon->_szCard);
}

PINDialog::~PINDialog()
{
}

BOOL PINDialog::Populate()
{
	BOOL fReturn = FALSE;
	_pCredentialList.ConnectNotification(_szReader,_szCard,0);
	if (_pCredentialList.HasContainerHolder())
	{
		pCredential = _pCredentialList.GetContainerHolderAt(0);
		fReturn = TRUE;
	}
	return fReturn;
}

int PINDialog::Show()
{
    return _pWinLogon->DialogBoxParam(GetMyInstance(), MAKEINTRESOURCE(IDD_PIN), 0, _dialogProc, (LPARAM)this);
}

INT_PTR CALLBACK PINDialog::_dialogProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
    if (WM_INITDIALOG == msg) {
        ((PINDialog*)lp)->_hwnd = hwnd;
        SetWindowLongPtr(hwnd, GWLP_USERDATA, lp);
        PINDialog::CenterWindow(hwnd);
    }
	PINDialog* dlg = (PINDialog*)GetWindowLongPtr(hwnd, GWLP_USERDATA);

    // WM_SETFONT is coming in before WM_INITDIALOG
    // in which case GWLP_USERDATA won't be set yet.
	if (dlg) {
		return dlg->DialogProc(msg, wp, lp);
	}
    return FALSE;
}

INT_PTR PINDialog::DialogProc(UINT msg, WPARAM wp, LPARAM lParam)
{
    switch (msg) 
	{
	case WM_INITDIALOG:
		{
			DWORD dwCount = _pCredentialList.ContainerHolderCount();
			_pWinLogon->_LastHwndUsed = _hwnd;
			if (dwCount > 0)
			{
				SendMessage(GetDlgItem(this->_hwnd,IDC_CONTAINER),CB_RESETCONTENT,0,0);
				for (DWORD i = 0; i< dwCount; i++)
				{
					DWORD dwRid = _pCredentialList.GetContainerHolderAt(i)->GetContainer()->GetRid();
					PWSTR szName = GetUsernameFromRid(dwRid);
					if (szName)
					{
						SendMessage(GetDlgItem(this->_hwnd,IDC_CONTAINER),CB_INSERTSTRING,i,(LPARAM) szName);
						EIDFree(szName);
					}
				}
				SendMessage(GetDlgItem(this->_hwnd,IDC_CONTAINER),CB_SETCURSEL,0,0);
				SendMessage(_hwnd, WM_NEXTDLGCTL, (WPARAM)GetDlgItem(this->_hwnd,IDC_PIN), TRUE);
			}
		}
		break;
	case WM_COMMAND: {
            switch (LOWORD(wp)) {
                case IDOK:
                    {
						DWORD index = SendMessage(GetDlgItem(_hwnd,IDC_CONTAINER),CB_GETCURSEL,0,0);
						pCredential = _pCredentialList.GetContainerHolderAt(index);
						GetWindowText(GetDlgItem(_hwnd,IDC_PIN), szPin, ARRAYSIZE(szPin));
						EndDialog(_hwnd, IDOK);
						break;
					}
                case IDCANCEL:
                    EndDialog(_hwnd, IDCANCEL);
                    break;
            }
            return TRUE;
        }
	case WLX_WM_SAS:
		// cancel Ctrl-Alt-Del SAS notification
		if (wp == WLX_SAS_TYPE_CTRL_ALT_DEL)
		{
			return TRUE;
		}
		break;
	case WM_EID_REMOVE:
		 EndDialog(_hwnd, IDCANCEL);
         break;
    }
	return FALSE;
}

void PINDialog::CenterWindow(HWND hwnd) {
    RECT rc;
    if (!GetWindowRect(hwnd, &rc)) return;

    const int width  = rc.right  - rc.left;
    const int height = rc.bottom - rc.top;

    MoveWindow(hwnd,
        (GetSystemMetrics(SM_CXSCREEN) - width)  / 2,
        (GetSystemMetrics(SM_CYSCREEN) - height) / 2,
        width, height, true);
}