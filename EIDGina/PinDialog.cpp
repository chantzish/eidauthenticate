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
    switch (msg) {
        case WM_COMMAND: {
            switch (LOWORD(wp)) {
                case IDOK:
                    GuiHelper::ExtractControlText(_hwnd, IDC_PIN,     &pin);
                    EndDialog(_hwnd, IDOK);
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
