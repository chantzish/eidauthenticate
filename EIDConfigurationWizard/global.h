
extern HINSTANCE g_hinst;

extern BOOL fHasAlreadySmartCardCredential;
extern BOOL fShowNewCertificatePanel;
extern BOOL fGotoNewScreen;

extern WCHAR szReader[];
extern DWORD dwReaderSize;
extern WCHAR szCard[];
extern DWORD dwCardSize;

VOID CenterWindow(HWND hWnd);
BOOL IsElevated();
BOOL ChangeRemovePolicy(BOOL fActivate);
BOOL ChangeForceSmartCardLogonPolicy(BOOL fActivate);
BOOL RenameAccount(PTSTR szNewUsername);

