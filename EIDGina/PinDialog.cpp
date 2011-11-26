// LogonDialog.cpp
//
// Gather user credentials for Logon.
//

#include "stdafx.h"
#include <WinCrypt.h>
#include "GinaSmartCardCredential.h"
#include "PinDialog.h"
#include "GuiHelper.h"

#include "resource.h"



INT_PTR PinDialog::DialogProc(UINT msg, WPARAM wp, LPARAM lp) {
    switch (msg) 
	{
		case WM_INITDIALOG:
			SendMessage(GetDlgItem(this->_hwnd,IDC_CONTAINER),CB_RESETCONTENT,0,0);
			if (_pCredentialList->HasContainerHolder())
			{
				for (DWORD i = 0; i< _pCredentialList->ContainerHolderCount(); i++)
				{
					SendMessage(GetDlgItem(this->_hwnd,IDC_CONTAINER),CB_INSERTSTRING,i,(LPARAM) _pCredentialList->GetContainerHolderAt(i)->GetContainer()->GetContainerName());
				}
				SendMessage(GetDlgItem(this->_hwnd,IDC_CONTAINER),CB_SETCURSEL,0,0);
			}
			break;
		case WM_COMMAND: {
            switch (LOWORD(wp)) {
                case IDOK:
                    GuiHelper::ExtractControlText(_hwnd, IDC_PIN,     &pin);
                    EndDialog(_hwnd, IDOK);
					if (_pCredentialList->ContainerHolderCount() > 0)
					{
						certificate = _pCredentialList->GetContainerHolderAt(0);
					}
                    break;
                case IDCANCEL:
                    EndDialog(_hwnd, IDCANCEL);
                    break;
            }
            return TRUE;
        }
    }
    return FALSE;
}
