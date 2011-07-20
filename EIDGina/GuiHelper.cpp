// GuiHelper.cpp
//
// Common utilities for window management.
//

#include "stdafx.h"
#include "GUIHelper.h"

#pragma warning(push)
#pragma warning(disable : 4244)

void GuiHelper::SetWindowLongPointer(HWND hwnd, int index, LONG_PTR dwNewLong) {
    SetWindowLongPtr(hwnd, index, dwNewLong);
}

LONG_PTR GuiHelper::GetWindowLongPointer(HWND hwnd, int index) {
    return GetWindowLongPtr(hwnd, index);
}

#pragma warning(pop)

void GuiHelper::CenterWindow(HWND hwnd) {
    RECT rc;
    if (!GetWindowRect(hwnd, &rc)) return;

    const int width  = rc.right  - rc.left;
    const int height = rc.bottom - rc.top;

    MoveWindow(hwnd,
        (GetSystemMetrics(SM_CXSCREEN) - width)  / 2,
        (GetSystemMetrics(SM_CYSCREEN) - height) / 2,
        width, height, true);
}

bool GuiHelper::SetControlText(HWND hDlg, int id, const wchar_t* pText) {
    HWND hwnd = GetDlgItem(hDlg, id);
    if (!hwnd) return false;

    return SetWindowText(hwnd, pText ? pText : L"") ? true : false;
}

bool GuiHelper::ExtractControlText(HWND hDlg, int id, wchar_t** ppText) {
    HWND hwnd = GetDlgItem(hDlg, id);
    if (!hwnd) return false;

    const int cch = GetWindowTextLength(hwnd);
    const int cchMax = cch + 1;
    *ppText = new wchar_t[cchMax];
    if (!*ppText) {
        LOOM;
        return false;
    }

    return cch == GetWindowText(hwnd, *ppText, cchMax);
}

extern "C"
{
	typedef DWORD (WINAPI *ThemeWaitForServiceReadyFct) (DWORD dwTimeout);
	typedef BOOL (WINAPI *ThemeWatchForStartFct) (void);
}

#define SM_SHSVCS_TIMEOUT 1000
#define ThemeWatchForStart_Ordinal 1
#define ThemeWaitForServiceReady_Ordinal 2 
bool GuiHelper::EnableWindowsXPTheme()
{
	bool returnCode = false;
	ThemeWaitForServiceReadyFct ThemeWaitForServiceReady = NULL;
	ThemeWatchForStartFct ThemeWatchForStart = NULL;
	HMODULE hModule = NULL;
	__try
	{
		hModule = LoadLibrary(TEXT("Shsvcs.dll"));
		if (hModule == NULL)
		{
			__leave;
		}
		ThemeWaitForServiceReady = (ThemeWaitForServiceReadyFct) GetProcAddress(hModule, (LPCSTR)(ThemeWaitForServiceReady_Ordinal));
		ThemeWatchForStart = (ThemeWatchForStartFct) GetProcAddress(hModule,  (LPCSTR)(ThemeWatchForStart_Ordinal));
		if (ThemeWaitForServiceReady == NULL || ThemeWatchForStart == NULL)
		{
			__leave;
		}
		DWORD dwResult = ThemeWaitForServiceReady(SM_SHSVCS_TIMEOUT);
		// Give it Plenty of Time, Just in case
		for (int iWait = 0; ((WAIT_OBJECT_0 != dwResult) && (iWait < 30)); ++iWait) {
			dwResult = ThemeWaitForServiceReady(SM_SHSVCS_TIMEOUT);
		}
		// See if it is Ready
		if (WAIT_OBJECT_0 == dwResult) {
			// Now Set the Internal State to permit theme functionality
			BOOL bResult = ThemeWatchForStart();
			if (bResult) 
			{
				returnCode = true;
			}
			else
			{
				//error
			}
		}
		else
		{
			//error
		}
	}
	__finally
	{
		if (hModule) FreeLibrary(hModule);
	}
	return returnCode;
}